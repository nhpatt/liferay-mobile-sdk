package com.liferay.mobile.android.auth;

import android.net.Uri;
import com.liferay.mobile.android.auth.oauth2.OAuth2Authentication;
import com.liferay.mobile.android.exception.ServerException;
import com.liferay.mobile.android.service.Session;
import com.liferay.mobile.android.service.SessionImpl;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.Credentials;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ClientSecretBasic;
import org.json.JSONException;
import org.json.JSONObject;
import com.liferay.mobile.android.http.Headers;

public class OAuth2SignIn {

	public static Session signInWithUsernameAndPassword(final String username, final String password, Session session,
		String clientId, String clientSecret, List<String> scopes, SessionCallback callback) throws Exception {

		Map<String, String> parameters = new HashMap<String, String>() {{
			put("username", username);
			put("password", password);
			put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
		}};

		return sendTokenRequest(session, clientId, clientSecret, parameters, callback);
	}

	public static Session clientCredentialsSignIn(Session session, String clientId, String clientSecret,
		List<String> scopes, SessionCallback callback) throws Exception {

		Map<String, String> parameters = new HashMap<String, String>() {{
			put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
		}};

		return sendTokenRequest(session, clientId, clientSecret, parameters, callback);
	}

	public static Session refreshToken(Session session, List<String> scopes, SessionCallback callback)
		throws Exception {

		if (!(session.getAuthentication() instanceof OAuth2Authentication)) {
			throw new IllegalAccessException("Authentication should be of type OAuth2Authentication");
		}

		final OAuth2Authentication authentication = (OAuth2Authentication) session.getAuthentication();

		Map<String, String> parameters = new HashMap<String, String>() {{
			put("refresh_token", authentication.getRefreshToken());
			put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
		}};

		Session oauth2Session = sendTokenRequest(session,
			authentication.getClientId(), authentication.getClientSecret(), parameters, callback);

		OAuth2Authentication oauth2Auth = (OAuth2Authentication) oauth2Session.getAuthentication();

		authentication.setAccessTokenExpirationDate(oauth2Auth.getAccessTokenExpirationDate());
		authentication.setAccessToken(oauth2Auth.getAccessToken());
		authentication.setRefreshToken(oauth2Auth.getRefreshToken());
		authentication.setScope(oauth2Auth.getScope());

		return session;
	}

	public static void setPaths(String tokenPath, String authorizationPath) {
		_TOKEN_PATH = tokenPath;
		_AUTHORIZATION_PATH = authorizationPath;
	}

	private static Session sendTokenRequest(final Session session, final String clientId, final String clientSecret,
		Map<String, String> parameters, final SessionCallback callback) throws Exception {

		OkHttpClient client = new OkHttpClient();
		FormEncodingBuilder formBody = new FormEncodingBuilder();

		for (Map.Entry<String, String> parameter : parameters.entrySet()) {
			formBody.add(parameter.getKey(), parameter.getValue());
		}

		RequestBody body = formBody.build();

		String tokenUrl = getServerURL(session.getServer()) + _TOKEN_PATH;

		Request request = new Request.Builder().url(tokenUrl)
			.header(Headers.AUTHORIZATION, Credentials.basic(clientId, clientSecret))
			.post(body)
			.build();

		final Call call = client.newCall(request);

		if (callback == null) {
			return parseRespone(call.execute(), session, clientId, clientSecret);
		} else {
			call.enqueue(new Callback() {
				@Override
				public void onFailure(Request request, IOException e) {
					callback.onFailure(e);
				}

				@Override
				public void onResponse(Response response) {
					try {
						callback.onSuccess(parseRespone(response, session, clientId, clientSecret));
					} catch (Exception ex) {
						callback.onFailure(ex);
					}
				}
			});

			return null;
		}
	}

	private static Session parseRespone(Response response, Session session, String clienId, String clientSecret)
		throws Exception {
		if (!response.isSuccessful()) {
			throw new ServerException(response.message());
		}

		OAuth2Authentication auth = parseJsonToken(response, clienId, clientSecret);

		Session oauth2Session = new SessionImpl(session);
		oauth2Session.setAuthentication(auth);

		return oauth2Session;
	}

	private static OAuth2Authentication parseJsonToken(Response response, String clienId, String clientSecret)
		throws Exception {
		try {
			JSONObject jsonObject = new JSONObject(response.body().string());

			String accessToken = jsonObject.getString("access_token");
			long expirationTime = jsonObject.getLong("expires_in");
			String scope = jsonObject.getString("scope");
			String refreshToken = jsonObject.optString("refresh_token");

			long expirationDate = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) + expirationTime;
			List<String> scopes = Arrays.asList(scope.split(" "));

			return new OAuth2Authentication(accessToken, refreshToken, scopes, expirationDate, clienId, clientSecret);
		} catch (JSONException e) {
			throw new ServerException("Invalid json");
		}
	}

	private static AuthorizationServiceConfiguration getAuthorizationServiceConfiguration(String server) {
		String parsedServer = getServerURL(server);

		Uri authorizationUri = Uri.parse(parsedServer + _AUTHORIZATION_PATH);
		Uri tokenUri = Uri.parse(parsedServer + _TOKEN_PATH);

		return new AuthorizationServiceConfiguration(authorizationUri, tokenUri);
	}

	private static String getServerURL(String server) {
		return server.endsWith("/") ? server : server + "/";
	}

	private static String _AUTHORIZATION_PATH = "o/oauth2/authorize";
	private static String _TOKEN_PATH = "o/oauth2/token";

	private static final String GRANT_TYPE = "grant_type";

	private static final String GRANT_TYPE_PASSWORD = "password";
	private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
	private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
}
