/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Request (and Consent)
 * used in the Authorization Code Grant.
 *
 * 授权码授予流的 OAuth2.0 授权请求的  AuthenticationProvider 实现 ...
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	// 默认的状态key 生成器 ...
	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private static final Function<String, OAuth2AuthenticationValidator> DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER =
			createDefaultAuthenticationValidatorResolver();
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2AuthorizationConsentService authorizationConsentService;
	// 授权码生成器..
	private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
	private Function<String, OAuth2AuthenticationValidator> authenticationValidatorResolver = DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER;
	private Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		return authorizationCodeRequestAuthentication.isConsent() ?
				authenticateAuthorizationConsent(authentication) :
				// 先认证通过才行 ...
				authenticateAuthorizationRequest(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}.
	 *
	 * @param authorizationCodeGenerator the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}
	 * @since 0.2.3
	 */
	public void setAuthorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
		Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
		this.authorizationCodeGenerator = authorizationCodeGenerator;
	}

	/**
	 * Sets the resolver that resolves an {@link OAuth2AuthenticationValidator} from the provided OAuth 2.0 Authorization Request parameter.
	 *
	 * <p>
	 * The following OAuth 2.0 Authorization Request parameters are supported:
	 * <ol>
	 * <li>{@link OAuth2ParameterNames#REDIRECT_URI}</li>
	 * <li>{@link OAuth2ParameterNames#SCOPE}</li>
	 * </ol>
	 *
	 * <p>
	 * <b>NOTE:</b> The resolved {@link OAuth2AuthenticationValidator} MUST throw {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
	 *
	 * @param authenticationValidatorResolver the resolver that resolves an {@link OAuth2AuthenticationValidator} from the provided OAuth 2.0 Authorization Request parameter
	 */
	public void setAuthenticationValidatorResolver(Function<String, OAuth2AuthenticationValidator> authenticationValidatorResolver) {
		Assert.notNull(authenticationValidatorResolver, "authenticationValidatorResolver cannot be null");
		this.authenticationValidatorResolver = authenticationValidatorResolver;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link OAuth2AuthorizationConsentAuthenticationContext}
	 * containing an {@link OAuth2AuthorizationConsent.Builder} and additional context information.
	 *
	 * <p>
	 * The following context attributes are available:
	 * <ul>
	 * <li>The {@link OAuth2AuthorizationConsent.Builder} used to build the authorization consent
	 * prior to {@link OAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}.</li>
	 * <li>The {@link Authentication} of type
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.</li>
	 * <li>The {@link RegisteredClient} associated with the authorization request.</li>
	 * <li>The {@link OAuth2Authorization} associated with the state token presented in the
	 * authorization consent request.</li>
	 * <li>The {@link OAuth2AuthorizationRequest} associated with the authorization consent request.</li>
	 * </ul>
	 *
	 * @param authorizationConsentCustomizer the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationConsentAuthenticationContext} containing an {@link OAuth2AuthorizationConsent.Builder}
	 */
	public void setAuthorizationConsentCustomizer(Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer) {
		Assert.notNull(authorizationConsentCustomizer, "authorizationConsentCustomizer cannot be null");
		this.authorizationConsentCustomizer = authorizationConsentCustomizer;
	}

	// 来到这里 认证 ..
	private Authentication authenticateAuthorizationRequest(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		// 从 注册的client repository 中获取 已经注册的 client ...
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		// 拿不到直接返回错误 ..
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, null);
		}

		Map<Object, Object> context = new HashMap<>();
		// 注册的Client ...
		context.put(RegisteredClient.class, registeredClient);

		// 产生 OAuth2 认证上下文 ...
		OAuth2AuthenticationContext authenticationContext = new OAuth2AuthenticationContext(
				authorizationCodeRequestAuthentication, context);

		// 解析认证校验器 ...
		OAuth2AuthenticationValidator redirectUriValidator = resolveAuthenticationValidator(OAuth2ParameterNames.REDIRECT_URI);
		// 验证重定向 ..
		redirectUriValidator.validate(authenticationContext);

		// 如果不是授权码授予类型 ...
		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			// 抛出异常,未授权的客户端  ...
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		// 获取 scope 验证其 .. 进行验证 ..
		OAuth2AuthenticationValidator scopeValidator = resolveAuthenticationValidator(OAuth2ParameterNames.SCOPE);
		scopeValidator.validate(authenticationContext);

		// 对于 public client(进行 code_challenge) .. -RFC 7636(PKCE) ..
		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
		// 如果存在
		if (StringUtils.hasText(codeChallenge)) {
			// 获取方法 ..
			String codeChallengeMethod = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
			// 如果没有或者方法不是 s256 ...
			if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
						authorizationCodeRequestAuthentication, registeredClient, null);
			}
			// 需要 Proof key
		} else if (registeredClient.getClientSettings().isRequireProofKey()) {
			// 也就是 必须提供 code_challenge ...
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
					authorizationCodeRequestAuthentication, registeredClient, null);
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		// 确保资源拥有者是认证了的 ...
		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		// 拿取身份,判断是否认证 ..
		if (!isPrincipalAuthenticated(principal)) {
			// Return the authorization request as-is where isAuthenticated() is false
			// 没有认证的情况下,直接返回 ...
			return authorizationCodeRequestAuthentication;
		}

		// 如果是认证了的 ...
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.build();

		// 从当前的授权赞成service 中获取 有关信息 ...
		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), principal.getName());

		// 需要许可的 限制  ..,然后许可成功之后,就跳过这个阶段 ...
		if (requireAuthorizationConsent(registeredClient, authorizationRequest, currentAuthorizationConsent)) {
			// 重新生成 state ...
			String state = DEFAULT_STATE_GENERATOR.generateKey();
			// 然后构造授权 ...
			OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
					.attribute(OAuth2ParameterNames.STATE, state)
					.build();
			// 然后保存 ..
			this.authorizationService.save(authorization);

			// 当前的 不为空,则获取当前授权的scopes ...
			Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
					currentAuthorizationConsent.getScopes() : null;

			// 然后返回 ..
			return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
					.authorizationUri(authorizationRequest.getAuthorizationUri())
					.scopes(currentAuthorizedScopes)
					.state(state)
					.consentRequired(true)
					.build();
		}

		// 否则创建  OAuth2TokenContext
		OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
				authorizationCodeRequestAuthentication, registeredClient, null, authorizationRequest.getScopes());

		// 然后授权码生成器会使用它 生成授权码
		OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
		if (authorizationCode == null) {
			// 这就是服务器的问题了 ...
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the authorization code.", ERROR_URI);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}

		// 然后生成一个OAuth2Authorization ..
		OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
				.authorizedScopes(authorizationRequest.getScopes())
				.token(authorizationCode)
				.build();

		// 保存登录的信息 ...
		this.authorizationService.save(authorization);

		// 然后获取重定向uri ...
		String redirectUri = authorizationRequest.getRedirectUri();
		// 如果不存在,随便拿取一个 ..
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		// 然后生成 授权码请求 认证 token ... 并将授权码返回给客户端 ...
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizationRequest.getScopes())
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private OAuth2AuthenticationValidator resolveAuthenticationValidator(String parameterName) {
		// 如果存在,则返回,否则 默认返回的验证器解析器 返回一个 ...
		OAuth2AuthenticationValidator authenticationValidator = this.authenticationValidatorResolver.apply(parameterName);
		return authenticationValidator != null ?
				authenticationValidator :
				DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER.apply(parameterName);
	}

	private Authentication authenticateAuthorizationConsent(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeRequestAuthentication.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		// The 'in-flight' authorization must be associated to the current principal
		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> requestedScopes = authorizationRequest.getScopes();
		Set<String> authorizedScopes = new HashSet<>(authorizationCodeRequestAuthentication.getScopes());
		if (!requestedScopes.containsAll(authorizedScopes)) {
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				authorization.getRegisteredClientId(), authorization.getPrincipalName());
		Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
				currentAuthorizationConsent.getScopes() : Collections.emptySet();

		if (!currentAuthorizedScopes.isEmpty()) {
			for (String requestedScope : requestedScopes) {
				if (currentAuthorizedScopes.contains(requestedScope)) {
					authorizedScopes.add(requestedScope);
				}
			}
		}

		if (!authorizedScopes.isEmpty() && requestedScopes.contains(OidcScopes.OPENID)) {
			// 'openid' scope is auto-approved as it does not require consent
			authorizedScopes.add(OidcScopes.OPENID);
		}

		OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
		if (currentAuthorizationConsent != null) {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
		} else {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(
					authorization.getRegisteredClientId(), authorization.getPrincipalName());
		}
		authorizedScopes.forEach(authorizationConsentBuilder::scope);

		if (this.authorizationConsentCustomizer != null) {
			// @formatter:off
			OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
					OAuth2AuthorizationConsentAuthenticationContext.with(authorizationCodeRequestAuthentication)
							.authorizationConsent(authorizationConsentBuilder)
							.registeredClient(registeredClient)
							.authorization(authorization)
							.authorizationRequest(authorizationRequest)
							.build();
			// @formatter:on
			this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
		}

		Set<GrantedAuthority> authorities = new HashSet<>();
		authorizationConsentBuilder.authorities(authorities::addAll);

		if (authorities.isEmpty()) {
			// Authorization consent denied (or revoked)
			if (currentAuthorizationConsent != null) {
				this.authorizationConsentService.remove(currentAuthorizationConsent);
			}
			this.authorizationService.remove(authorization);
			throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
		if (!authorizationConsent.equals(currentAuthorizationConsent)) {
			this.authorizationConsentService.save(authorizationConsent);
		}

		OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
				authorizationCodeRequestAuthentication, registeredClient, authorization, authorizedScopes);
		OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
		if (authorizationCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the authorization code.", ERROR_URI);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}

		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
				.authorizedScopes(authorizedScopes)
				.token(authorizationCode)
				.attributes(attrs -> {
					attrs.remove(OAuth2ParameterNames.STATE);
				})
				.build();
		this.authorizationService.save(updatedAuthorization);

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizedScopes)
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private static Function<String, OAuth2AuthenticationValidator> createDefaultAuthenticationValidatorResolver() {
		Map<String, OAuth2AuthenticationValidator> authenticationValidators = new HashMap<>();
		authenticationValidators.put(OAuth2ParameterNames.REDIRECT_URI, new DefaultRedirectUriOAuth2AuthenticationValidator());
		authenticationValidators.put(OAuth2ParameterNames.SCOPE, new DefaultScopeOAuth2AuthenticationValidator());
		return authenticationValidators::get;
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient, Authentication principal,
			OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private static OAuth2TokenContext createAuthorizationCodeTokenContext(
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.providerContext(ProviderContextHolder.getProviderContext())
				.tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeRequestAuthentication);
		// @formatter:on

		if (authorization != null) {
			tokenContextBuilder.authorization(authorization);
		}

		return tokenContextBuilder.build();
	}

	// 是否需要 consent ..
	private static boolean requireAuthorizationConsent(RegisteredClient registeredClient,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationConsent authorizationConsent) {

		// 如果不需要, 直接返回 ..
		if (!registeredClient.getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}
		// openid 不需要 consent ..
		// 这也就是google 为什么直接就登录了 ...
		// 'openid' scope does not require consent
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID) &&
				authorizationRequest.getScopes().size() == 1) {
			return false;
		}
		// 否则, 判断赞同的scopes 包含了请求的 scopes ....
		if (authorizationConsent != null &&
				authorizationConsent.getScopes().containsAll(authorizationRequest.getScopes())) {
			return false;
		}

		return true;
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, authorizationCodeRequestAuthentication, registeredClient, null);
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		throwError(errorCode, parameterName, ERROR_URI,
				authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

		boolean redirectOnError = true;

		// 无效请求, client_id / redirect_uri / state 不重定向 ..
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
				(parameterName.equals(OAuth2ParameterNames.CLIENT_ID) ||
						parameterName.equals(OAuth2ParameterNames.REDIRECT_URI) ||
						parameterName.equals(OAuth2ParameterNames.STATE))) {
			redirectOnError = false;
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = authorizationCodeRequestAuthentication;

		if (redirectOnError && !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			// 从客户端配置中解析 redirect_uri ...
			String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
			// 这很正常,要求 state 请求和响应必须匹配 ...
			// 并且如果是 consent 则 返回 授权请求的 getState ... / 否则 返回认证的 state ...
			String state = authorizationCodeRequestAuthentication.isConsent() && authorizationRequest != null ?
					authorizationRequest.getState() : authorizationCodeRequestAuthentication.getState();

			//
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					.redirectUri(redirectUri)
					.state(state)
					.build();
			// 设置是否认证完成 ...
			authorizationCodeRequestAuthenticationResult.setAuthenticated(authorizationCodeRequestAuthentication.isAuthenticated());
		} else if (!redirectOnError && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			// 不重定向,但是存在重定向地址 ...
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					// 阻止重定向 ...
					.redirectUri(null)		// Prevent redirects
					.build();
			authorizationCodeRequestAuthenticationResult.setAuthenticated(authorizationCodeRequestAuthentication.isAuthenticated());
		}

		// 抛出这个异常 ...
		// 包含了异常和 authentication ..
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
	}

	private static String resolveRedirectUri(OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {
		if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
			return authorizationRequest.getRedirectUri();
		}
		if (registeredClient != null) {
			return registeredClient.getRedirectUris().iterator().next();
		}
		return null;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder from(OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(authorizationCodeRequestAuthentication.getClientId(), (Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.authorizationCode(authorizationCodeRequestAuthentication.getAuthorizationCode());
	}

	private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {
		private final StringKeyGenerator authorizationCodeGenerator =
				new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

		@Nullable
		@Override
		public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {

			if (context.getTokenType() == null ||
					!OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			// 标识Token 授权码存活时间 ...
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
			// 然后生成一个key
			return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
		}

	}

	/**
	 * 也就是校验重定向uri 的合法性 ...
	 */
	private static class DefaultRedirectUriOAuth2AuthenticationValidator implements OAuth2AuthenticationValidator {

		@Override
		public void validate(OAuth2AuthenticationContext authenticationContext) {

			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();
			RegisteredClient registeredClient = authenticationContext.get(RegisteredClient.class);

			// 拿取请求中的重定向地址 ...
			String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

			if (StringUtils.hasText(requestedRedirectUri)) {
				// ***** redirect_uri is available in authorization request

				UriComponents requestedRedirect = null;
				try {
					requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();
				} catch (Exception ex) { }

				// 如果为空,则报错 ... 或者包含碎片值 # ... 也成为瞄点值 ..
				if (requestedRedirect == null || requestedRedirect.getFragment() != null) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient);
				}

				// 拿取Host ...
				String requestedRedirectHost = requestedRedirect.getHost();
//				  判断如果为空,或者为 localhsot
				if (requestedRedirectHost == null || requestedRedirectHost.equals("localhost")) {
					// As per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-01#section-9.7.1
					// 规范告诉我们应该使用类似循环ip地址,但是不应该使用localhost ,127.0.0.1 是一个好的选择 .....
					// While redirect URIs using localhost (i.e., "http://localhost:{port}/{path}")
					// function similarly to loopback IP redirects described in Section 10.3.3,
					// the use of "localhost" is NOT RECOMMENDED.
					OAuth2Error error = new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST,
							"localhost is not allowed for the redirect_uri (" + requestedRedirectUri + "). " +
									"Use the IP literal (127.0.0.1) instead.",
							"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-01#section-9.7.1");
					throwError(error, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient, null);
				}

				// 如果不是回环地址 ...
				if (!isLoopbackAddress(requestedRedirectHost)) {
					// As per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-01#section-9.7
					// When comparing client redirect URIs against pre-registered URIs,
					// authorization servers MUST utilize exact string matching.
					// 客户端返回的重定向地址必须是预先配置好的URIs ....
					// 进行比较 ...
					if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
						throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
								authorizationCodeRequestAuthentication, registeredClient);
					}
				} else {
					// As per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-01#section-10.3.3
					// The authorization server MUST allow any port to be specified at the
					// time of the request for loopback IP redirect URIs, to accommodate
					// clients that obtain an available ephemeral port from the operating
					// system at the time of the request.

					// 否则 授权服务器必须允许任何端口(在此时请求,从请求中获取目标端口 ...)进行会话地址IP 从定向URI 拼接 ...
//					为了适应客户端获取一个可用的短暂的端口(从操作系统中)进行请求
					boolean validRedirectUri = false;

					// 但是它还是匹配Url 是否匹配对应的port ...
					for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
						UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
						registeredRedirect.port(requestedRedirect.getPort());
						if (registeredRedirect.build().toString().equals(requestedRedirect.toString())) {
							validRedirectUri = true;
							break;
						}
					}
					// 如果无效,则返回 无效请求,重定向 URI 的问题 ...
					if (!validRedirectUri) {
						throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
								authorizationCodeRequestAuthentication, registeredClient);
					}
				}

			} else {
				// ***** redirect_uri is NOT available in authorization request
				// 否则抛出异常 ... 如果包含OPENID 或者 重定向URI 不止一个 ...
				if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID) ||
						registeredClient.getRedirectUris().size() != 1) {
					// redirect_uri is REQUIRED for OpenID Connect
					// OPenID Connect 必须在请求中包含重定向地址 ...
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient);
				}

				// 没有就不处理 ....
			}
		}

		private static boolean isLoopbackAddress(String host) {
			// IPv6 loopback address should either be "0:0:0:0:0:0:0:1" or "::1"
			if ("[0:0:0:0:0:0:0:1]".equals(host) || "[::1]".equals(host)) {
				return true;
			}
			// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
			String[] ipv4Octets = host.split("\\.");
			if (ipv4Octets.length != 4) {
				return false;
			}
			try {
				int[] address = new int[ipv4Octets.length];
				for (int i=0; i < ipv4Octets.length; i++) {
					address[i] = Integer.parseInt(ipv4Octets[i]);
				}
				return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 &&
						address[2] <= 255 && address[3] >= 1 && address[3] <= 255;
			} catch (NumberFormatException ex) {
				return false;
			}
		}

	}

	private static class DefaultScopeOAuth2AuthenticationValidator implements OAuth2AuthenticationValidator {

		@Override
		public void validate(OAuth2AuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();
			RegisteredClient registeredClient = authenticationContext.get(RegisteredClient.class);

			Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
			Set<String> allowedScopes = registeredClient.getScopes();

			// 允许的 scope 并没有包含所有请求的 .. 直接抛出异常
			if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
				throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}

	}

}
