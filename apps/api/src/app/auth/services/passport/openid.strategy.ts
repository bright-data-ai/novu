import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Metadata, StateStoreStoreCallback, StateStoreVerifyCallback } from 'passport-oauth2';
import { AuthProviderEnum } from '@novu/shared';
import { AuthService } from '../auth.service';
import * as OpenIDConnectStrategy from 'passport-openidconnect';

@Injectable()
export class OpenidStrategy extends PassportStrategy(OpenIDConnectStrategy, 'openid') {
  constructor(private authService: AuthService) {
    super({
      issuer: process.env.OPENID_OAUTH_ISSUER,
      authorizationURL: process.env.OPENID_OAUTH_AUTHORIZATION_URL,
      tokenURL: process.env.OPENID_OAUTH_TOKEN_URL,
      userInfoURL: process.env.OPENID_OAUTH_USER_INFO_URL,
      clientID: process.env.OPENID_OAUTH_CLIENT_ID,
      clientSecret: process.env.OPENID_OAUTH_CLIENT_SECRET,
      callbackURL: process.env.OPENID_OAUTH_REDIRECT,
      scope: ['email profile'],
      passReqToCallback: true,
      store: {
        verify(req, state: string, callback: StateStoreVerifyCallback) {
          callback(null, true, JSON.stringify(req.query));
        },
        store(req, ctx, state, meta: Metadata, callback: StateStoreStoreCallback) {
          callback(null, JSON.stringify(req.query));
        },
      },
    });
  }

  async validate(req, iss, userProfile, done: (err, data) => void) {
    try {
      const profile = { ...userProfile._json, email: userProfile.emails[0].value };
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
