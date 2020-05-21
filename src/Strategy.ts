/**
 *  Creator: Christian Hotz
 *  Company: hydra newmedia GmbH
 *  Date: 27.06.16
 *
 *  Copyright hydra newmedia GmbH
 */

/**
 *  Imports
 */
import { Request } from 'express';
import { Strategy as PassportStrategy } from 'passport-strategy';

export interface StrategyOptions {
  realm?: string;
  header: string;
  prefix: string;
  scope?: string | string[];
  passReqToCallback?: boolean;
}

export type VerifyFunction = (
  apiKey: string,
  done: (error: any, user?: any, info?: Object | string) => void
) => void;

export type VerifyFunctionWithRequest = (
  req: Request,
  apiKey: string,
  done: (error: any, user?: any, info?: Object | string) => void
) => void;

export class Strategy extends PassportStrategy {
  public readonly name: string;
  public readonly verify: VerifyFunction | VerifyFunctionWithRequest;
  private readonly prefixPattern: RegExp;

  private _options: StrategyOptions;

  get options(): StrategyOptions {
    return this._options;
  }

  constructor(
    options: StrategyOptions,
    verify: VerifyFunction | VerifyFunctionWithRequest
  ) {
    super();
    if (!options) {
      options = {} as StrategyOptions;
    }

    this._options = {
      realm: options.realm || 'Users',
      passReqToCallback: options.passReqToCallback ?? false,
      prefix: options.prefix ?? '',
      header: (options.header || 'X-Api-Key').toLowerCase()
    };

    if (options.scope) {
      this.options.scope = Array.isArray(options.scope)
        ? options.scope
        : [options.scope];
    }

    this.name = 'headerapikey';
    this.prefixPattern = new RegExp('^' + this._options.prefix, 'i');
    this.verify = verify;
  }

  public authenticate(req: Request): void {
    let apiKey: string | undefined = req.header(this._options.header);

    if (!apiKey) {
      return this.fail(this._challenge(), 401);
    }

    if (this.prefixPattern.test(apiKey)) {
      apiKey = apiKey.replace(this.prefixPattern, '').trim();
    } else {
      return this.fail(
        this._challenge(
          'invalid_prefix',
          `Invalid API key prefix, ${this._options.header} header should start with "${this._options.prefix}"`
        ),
        401
      );
    }

    const verified = (
      err: Error | null,
      user?: Object,
      info?: Object
    ): void => {
      if (err) {
        return this.error(err);
      }

      if (!user) {
        const message =
          typeof info === 'string' ? info : (info || ({} as any)).message;

        return this.fail(this._challenge('invalid_key', message), 401);
      }

      this.success(user, info);
    };

    const callbackParams = [req, apiKey, verified];

    if (!this._options.passReqToCallback) {
      callbackParams.shift();
    }

    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore
    this.verify(...callbackParams);
  }

  private _challenge(code?: string, desc?: string): string {
    // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
    let challenge =
      this._options.prefix + ' realm="' + this._options.realm + '"';

    if (this.options.scope) {
      challenge +=
        ', scope="' + (this.options.scope as string[]).join(' ') + '"';
    }

    if (code) {
      challenge += ', error="' + code + '"';
    }

    if (desc && desc.length) {
      challenge += ', error_description="' + desc + '"';
    }

    return challenge;
  }
}
