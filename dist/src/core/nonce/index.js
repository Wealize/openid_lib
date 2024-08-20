var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Result } from "../../common/classes/result.js";
import { InvalidNonceStage, NonceNotFound } from "../../common/index.js";
/**
 * Class that allows the management of the nonces generated together
 * with their states using an interface that simulates a key-value database.
 */
export class NonceManager {
    constructor(stateManager) {
        this.stateManager = stateManager;
    }
    // TODO: Evaluate the use of result
    /**
     * Allows to save a nonce and its associated state
     * @param id The nonce itself
     * @param data The data associated to the nonce
     */
    saveNonce(id, data) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.stateManager.saveState(id, data);
        });
    }
    /**
     * Allows to erase a nonce and its data
     * @param id The nonce to delete
     */
    deleteNonce(id) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.stateManager.deleteState(id);
        });
    }
    getNonce(id, expectedStage) {
        return __awaiter(this, void 0, void 0, function* () {
            const nonce = yield this.stateManager.getState(id);
            if (!nonce) {
                return Result.Err(new NonceNotFound(id));
            }
            if (nonce.type !== expectedStage) {
                return Result.Err(new InvalidNonceStage(id, expectedStage, nonce.type));
            }
            return Result.Ok(nonce);
        });
    }
    /**
     * Get the nonce specified and checks if its state if of the type "PostBaseAuthz"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getPostBaseAuthzNonce(id) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.getNonce(id, "PostBaseAuthz");
        });
    }
    /**
     * Get the nonce specified and checks if its state if of the type "DirectRequest"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getDirectRequestNonce(id) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.getNonce(id, "DirectRequest");
        });
    }
    /**
     * Get the nonce specified and checks if its state if of the type "PostAuthz"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getPostAuthz(id) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.getNonce(id, "PostAuthz");
        });
    }
    /**
     * Get the nonce specified and checks if its state if of the type "ChallengeNonce"
     * @param id The nonce itself to get its state
     * @returns The state of the nonce
     */
    getChallengeNonce(id) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.getNonce(id, "ChallengeNonce");
        });
    }
}
export * from "./types.js";
