/**
 * A class that implements a key-value interface to handle states.
 * The user of the library must generate an implementation in order
 * for a RP and a VcIssuer to work.
 */
export declare abstract class StateManager {
    /**
     * Save a chunck of data in a space reserved with the indicated ID
     * @param id The ID that identified the chunk data
     * @param data The data to store
     */
    abstract saveState(id: string, data: any): Promise<void>;
    abstract getState(id: string): Promise<any | undefined>;
    abstract deleteState(id: string): Promise<void>;
}
/**
 * Basic In-Memory implementation of the StateManager interface.
 * Its use is inteded for tests and development
 */
export declare class MemoryStateManager extends StateManager {
    private memory;
    constructor();
    saveState(id: string, data: any): Promise<void>;
    getState(id: string): Promise<any | undefined>;
    deleteState(id: string): Promise<void>;
}
