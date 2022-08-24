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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
 * for the OAuth 2.0 Authorization Code Grant and then converts it to
 * an {@link OAuth2AuthorizationCodeRequestAuthenticationToken} used for authenticating the request.
 *
 * 尝试从请求中抓取授权请求(或者 Consent)  - 为了进行OAuth2.0 授权码授予活动,然后将它转换为OAuth2AuthorizationCodeRequestAuthenticationToken 被用来认证请求 ....
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationEndpointFilter
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {
	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	// 匿名用户 ...
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private static final RequestMatcher OIDC_REQUEST_MATCHER = createOidcRequestMatcher();

	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		boolean authorizationRequest = false;

		// get / 或者 oidc ...
		// 在get的情况下, 表示一个授权码请求 ...
		// 它需要
		if ("GET".equals(request.getMethod()) || OIDC_REQUEST_MATCHER.matches(request)) {
			authorizationRequest = true;

			// response_type (REQUIRED),并且响应类型必须是  Code ....
			String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
			if (!StringUtils.hasText(responseType) ||
					parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
			} else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
				// 如果响应类型
				throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
			}
		}

		String authorizationUri = request.getRequestURL().toString();

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) ||
				parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// redirect_uri (OPTIONAL)
		// 重定向uri是可选的 ...
		String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.hasText(redirectUri) &&
				parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
		}

		// scope (OPTIONAL)
		// scope 可选的 ...
		Set<String> scopes = null;
		if (authorizationRequest) {
			String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
			if (StringUtils.hasText(scope) &&
					parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
			}
			if (StringUtils.hasText(scope)) {
				scopes = new HashSet<>(
						// 通过空格 分离 socpe ..
						Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
			}
		} else {
			// Consent request
			// 拿取所有的 scopes ...
			if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
				scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
			}
		}

		// state
		// RECOMMENDED for Authorization Request
		// state 授权请求中是推荐有的 ...
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (authorizationRequest) {
			// 可以没有 ...
			if (StringUtils.hasText(state) &&
					parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
			}
		} else {
			// REQUIRED for Authorization Consent Request
			// Consent 请求也需要 ...
			if (!StringUtils.hasText(state) ||
					parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
			}
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		// 有就判断 。。。
		String codeChallenge = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge) &&
				parameters.get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI);
		}

		// code_challenge_method (OPTIONAL for public clients) - RFC 7636 (PKCE)
		String codeChallengeMethod = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
		if (StringUtils.hasText(codeChallengeMethod) &&
				parameters.get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI);
		}
		// 额外的参数 ...
		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.RESPONSE_TYPE) &&
					!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
					!key.equals(OAuth2ParameterNames.REDIRECT_URI) &&
					!key.equals(OAuth2ParameterNames.SCOPE) &&
					!key.equals(OAuth2ParameterNames.STATE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		// 然后返回对应的  OAuth2AuthorizationCodeRequestAuthenticationToken ....
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, principal)
				.authorizationUri(authorizationUri)
				.redirectUri(redirectUri)
				.scopes(scopes)
				.state(state)
				.additionalParameters(additionalParameters)
				.consent(!authorizationRequest)
				.build();
	}

	// oidc 需要Post,且 响应类型不为空, 然后可以选择包含 scope ..
	private static RequestMatcher createOidcRequestMatcher() {
		RequestMatcher postMethodMatcher = request -> "POST".equals(request.getMethod());
		RequestMatcher responseTypeParameterMatcher = request ->
				request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
		RequestMatcher openidScopeMatcher = request -> {
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
		};
		return new AndRequestMatcher(
				postMethodMatcher, responseTypeParameterMatcher, openidScopeMatcher);
	}

	private static void throwError(String errorCode, String parameterName) {
		throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

}
