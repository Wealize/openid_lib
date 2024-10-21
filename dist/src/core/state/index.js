var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/**
 * A class that implements a key-value interface to handle states.
 * The user of the library must generate an implementation in order
 * for a RP and a VcIssuer to work.
 */
export class StateManager {
}
/**
 * Basic In-Memory implementation of the StateManager interface.
 * Its use is inteded for tests and development
 */
export class MemoryStateManager extends StateManager {
    constructor() {
        super();
        this.memory = {};
    }
    ;
    saveState(id, data) {
        return __awaiter(this, void 0, void 0, function* () {
            this.memory[id] = data;
        });
    }
    updateState(id, data) {
        return __awaiter(this, void 0, void 0, function* () {
            this.memory[id] = data;
        });
    }
    getState(id) {
        return this.memory[id];
    }
    deleteState(id) {
        return __awaiter(this, void 0, void 0, function* () {
            delete this.memory[id];
        });
    }
}
