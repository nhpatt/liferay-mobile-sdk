package com.liferay.mobile.android.auth.refresh;

import android.provider.Settings;
import com.liferay.mobile.android.auth.CookieSignIn;
import com.liferay.mobile.android.auth.OAuth2SignIn;
import com.liferay.mobile.android.auth.SessionCallback;
import com.liferay.mobile.android.auth.basic.CookieAuthentication;
import com.liferay.mobile.android.auth.oauth2.OAuth2Authentication;
import com.liferay.mobile.android.service.Session;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class OAuth2AuthenticationRefreshHandler implements AuthenticationRefreshHandler {

	@Override
	public Session refreshAuthentication(final Session session, final SessionCallback callback) throws Exception {

		OAuth2Authentication authentication = (OAuth2Authentication) session.getAuthentication();
		lock.lock();

		if (shouldRefreshToken(authentication.getAccessTokenExpirationDate())) {
			if (callback == null) {
				try {
					return OAuth2SignIn.refreshToken(session, authentication.getScope(), null);
				} finally {
					lock.unlock();
				}
			} else {

				OAuth2SignIn.refreshToken(session, authentication.getScope(), new SessionCallback() {
					@Override
					public void onSuccess(Session oauth2Session) {
						session.setAuthentication(oauth2Session.getAuthentication());

						lock.unlock();

						callback.onSuccess(session);
					}

					@Override
					public void onFailure(Exception e) {
						lock.unlock();

						callback.onFailure(e);
					}
				});

				return null;
			}
		} else {
			lock.unlock();
		}

		if (callback != null) {
			callback.onSuccess(session);

			return null;
		} else {
			return session;
		}
	}

	private boolean shouldRefreshToken(long accessTokenExpirationDate) {
		long currentTime = System.currentTimeMillis();

		long deltaTime = accessTokenExpirationDate - currentTime;

		return deltaTime <= TOLERANCE;
	}

	protected static final Lock lock = new ReentrantLock();
	private static final int TOLERANCE = 60;
}
