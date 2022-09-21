import { Injectable } from '@nestjs/common';
import { Metadata, StateStoreStoreCallback, StateStoreVerifyCallback } from 'passport-oauth2';
import { AuthProviderEnum } from '@novu/shared';
import { AuthService } from '../auth.service';
import * as OpenIDConnectStrategy from 'passport-openidconnect';
import * as passport from 'passport';

@Injectable()
export class OpenidStrategy extends OpenIDConnectStrategy {
  authService: AuthService;

  constructor(authService: AuthService) {
    const _callback = async (
      req,
      iss,
      uiProfile,
      idProfile,
      context,
      idToken,
      accessToken,
      refreshToken,
      params,
      done: (err, data) => void
    ) => {
      try {
        const validateResult = await this.validate(
          req,
          iss,
          uiProfile,
          idProfile,
          context,
          idToken,
          accessToken,
          refreshToken,
          params,
          done
        );
        done(null, validateResult);
      } catch (err) {
        done(err, null);
      }
    };
    Object.defineProperty(_callback, 'length', {
      value: 10,
    });
    super(
      {
        issuer: process.env.OPENID_OAUTH_ISSUER,
        authorizationURL: process.env.OPENID_OAUTH_AUTHORIZATION_URL,
        tokenURL: process.env.OPENID_OAUTH_TOKEN_URL,
        userInfoURL: process.env.OPENID_OAUTH_USER_INFO_URL,
        clientID: process.env.OPENID_OAUTH_CLIENT_ID,
        clientSecret: process.env.OPENID_OAUTH_CLIENT_SECRET,
        callbackURL: process.env.OPENID_OAUTH_REDIRECT,
        scope: ['email profile user_id'],
        passReqToCallback: true,
        store: {
          verify(req, state: string, callback: StateStoreVerifyCallback) {
            callback(null, true, JSON.stringify(req.query));
          },
          store(req, ctx, state, meta: Metadata, callback: StateStoreStoreCallback) {
            callback(null, JSON.stringify(req.query));
          },
        },
      },
      _callback
    );
    passport.use('openid', this);
    this.authService = authService;
  }

  async validate(
    req,
    iss,
    uiProfile,
    idProfile,
    context,
    idToken,
    accessToken,
    refreshToken,
    params,
    done: (err, data) => void
  ) {
    try {
      const profile = uiProfile._json;
      profile.id = String(profile.user_pk);
      profile.login = profile.preferred_username;
      const response = await this.authService.authenticate(
        AuthProviderEnum.OPENID,
        null,
        null,
        profile,
        this.parseState(req)?.distinctId
      );

      done(null, {
        token: response.token,
        newUser: response.newUser,
      });
    } catch (err) {
      done(err, false);
    }
  }

  private parseState(req) {
    try {
      return JSON.parse(req.query.state);
    } catch (e) {
      return {};
    }
  }
}
