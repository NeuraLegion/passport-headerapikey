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
import { HeaderAPIKeyStrategy, VerifyFunctionWithRequest } from '../../src';
import express, { Request } from 'express';
import sinon, { SinonSpy, SinonStub } from 'sinon';
import { expect } from 'chai';

describe("The HeaderAPIKeyStrategy's", () => {
  describe('constructor', () => {
    let testVerify: VerifyFunctionWithRequest = (
      _req: Request,
      _apiKey: string,
      verified: (err: Error | null, user?: Object, info?: Object) => void
    ) => {
      verified(null, { username: 'test' });
    };
    it('should set members properly', () => {
      let strategy: HeaderAPIKeyStrategy = new HeaderAPIKeyStrategy(
        {
          header: 'testheader',
          prefix: 'asdf',
          passReqToCallback: true
        },
        testVerify
      );
      expect(strategy.name).to.be.equal('headerapikey');
      expect(strategy.verify).to.equal(testVerify);
      expect(strategy.options.passReqToCallback).to.equal(true);
    });
    it("should default header member to 'X-Api-Key' without prefix", () => {
      let strategy: HeaderAPIKeyStrategy = new HeaderAPIKeyStrategy(
        null as any,
        testVerify
      );
      expect(strategy.options).to.be.ok;
      expect(strategy.options).to.deep.eq({
        header: 'x-api-key',
        prefix: '',
        realm: 'Users',
        passReqToCallback: false
      });
    });
    it('should default passReqToCallback member to false', () => {
      let strategy: HeaderAPIKeyStrategy = new HeaderAPIKeyStrategy(
        { header: 'apikey', prefix: '' },
        testVerify
      );
      expect(strategy.options.passReqToCallback).to.be.equal(false);
    });
  });
  describe('authenticate method', () => {
    let err: Error = new Error('something went wrong');
    let strategy: HeaderAPIKeyStrategy;
    let req: Request;
    let verify: SinonStub, fail: SinonSpy, success: SinonSpy, error: SinonSpy;
    before('setup mocks and spies', () => {
      verify = sinon.stub();
      verify.onFirstCall().yields(err);
      verify.onSecondCall().yields(null, null, { message: 'faily' });
      verify
        .onThirdCall()
        .yields(null, { username: 'testuser' }, { message: 'success' });
      strategy = new HeaderAPIKeyStrategy(
        {
          header: 'Authorization',
          prefix: 'Api-Key',
          passReqToCallback: true
        },
        verify
      );
      fail = strategy['fail'] = sinon.spy();
      success = strategy['success'] = sinon.spy();
      error = strategy['error'] = sinon.spy();
    });
    beforeEach('reset mocks and spies', () => {
      req = express().request;
      req.headers = { authorization: 'Api-Key topSecretApiKey' };
      fail.resetHistory();
      success.resetHistory();
      error.resetHistory();
    });

    it('should error if verify errors', () => {
      strategy.authenticate(req);
      expect(fail.called).not.to.be.ok;
      expect(success.called).not.to.be.ok;
      expect(error.calledOnce).to.be.ok;
      expect(error.getCall(0).args[0]).to.equal(err);
    });
    it('should fail if verify yields no user', () => {
      strategy.authenticate(req);
      expect(fail.calledOnce).to.be.ok;
      expect(fail.getCall(0).args[0]).to.eql(
        `${strategy.options.prefix} realm="${strategy.options.realm}", error="invalid_key", error_description="faily"`
      );
      expect(fail.getCall(0).args[1]).to.eql(401);
      expect(success.called).not.to.be.ok;
      expect(error.called).not.to.be.ok;
    });
    it('should succeed if verify succeeds', () => {
      strategy.authenticate(req);
      expect(fail.called).not.to.be.ok;
      expect(success.calledOnce).to.be.ok;
      expect(success.getCall(0).args[0]).to.eql({ username: 'testuser' });
      expect(success.getCall(0).args[1]).to.eql({ message: 'success' });
      expect(error.called).not.to.be.ok;
    });
    it('should get the correct api key from the headers', () => {
      strategy.authenticate(req);
      expect(verify.lastCall.args[1]).to.eql('topSecretApiKey');
    });
    it('should fail if no apikey set', () => {
      delete req.headers['authorization'];
      strategy.authenticate(req);
      expect(fail.calledOnce).to.be.ok;
      expect(fail.getCall(0).args[0]).to.equal(
        `${strategy.options.prefix} realm="${strategy.options.realm}"`
      );
      expect(fail.getCall(0).args[1]).to.eql(401);
      expect(success.called).not.to.be.ok;
      expect(error.called).not.to.be.ok;
    });
    it('should fail if empty apikey set', () => {
      req.headers['authorization'] = '';
      strategy.authenticate(req);
      expect(fail.calledOnce).to.be.ok;
      expect(fail.getCall(0).args[0]).to.equal(
        `${strategy.options.prefix} realm="${strategy.options.realm}"`
      );
      expect(fail.getCall(0).args[1]).to.eql(401);
      expect(success.called).not.to.be.ok;
      expect(error.called).not.to.be.ok;
    });
    it('should fail if apikey is prefixed in a false manner', () => {
      const err = `${strategy.options.prefix} realm="${strategy.options.realm}", error="invalid_prefix", error_description="Invalid API key prefix, authorization header should start with "${strategy.options.prefix}""`;
      req.headers['authorization'] = 'WrongPrefix mySuperduperApiKey';
      strategy.authenticate(req);
      expect(fail.calledOnce).to.be.ok;
      expect(fail.getCall(0).args[0]).to.be.equal(err);
      expect(fail.getCall(0).args[1]).to.eql(401);
      expect(success.called).not.to.be.ok;
      expect(error.called).not.to.be.ok;
    });
  });
});
