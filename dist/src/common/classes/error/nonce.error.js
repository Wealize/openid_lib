export class NonceError extends Error {
    constructor(nonceId) {
        super();
        this.nonceId = nonceId;
    }
}
export class NonceNotFound extends NonceError {
    constructor(nonceId) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message = `Nonce ${nonceId} not found`;
    }
}
export class InternalNonceError extends NonceError {
    constructor(nonceId) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message = `Internal error retrieving nonce ${nonceId}`;
    }
}
export class InvalidNonceStage extends NonceError {
    constructor(nonceId, expectedStage, currentStage) {
        super(nonceId);
        this.nonceId = nonceId;
        this.message =
            `Nonce ${nonceId} expected stage "${expectedStage}" but "${currentStage}" was found`;
    }
}
;
