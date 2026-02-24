/**
 * Utility function for byte operations
 */
import { Buffer } from "buffer";
import { Utilities } from "./utilities";
import { KyberService } from "../services/kyber.service";

/**
 * Generate a polynomial with coefficients distributed according to a
 * centered binomial distribution with parameter eta, given an array of
 * uniformly random bytes.
 *
 * @param buff
 * @param paramsK
 * @return
 */
export function generateCBDPoly(buff: Buffer, paramsK: number): number[] {
    const buf = Buffer.from(buff);
    const r = new Array<number>(KyberService.paramsPolyBytes);

    if (paramsK === 2) {
        for (let i = 0; i < KyberService.paramsN / 4; i++) {
            const t = convertByteTo24BitUnsignedInt(buf.slice(3 * i, buf.length));
            const d = t & 0x00249249 + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249);
            for (let j = 0; j < 4; j++) {
                const a = Utilities.int16((d >> (6 * j)) & 0x7);
                const b = Utilities.int16((d >> (6 * j + KyberService.paramsETAK512)) & 0x7);
                r[4 * i + j] = a - b;
            }
        }
        return r;
    }
    for (let i = 0; i < KyberService.paramsN / 8; i++) {
        const t = convertByteTo32BitUnsignedInt(buf.slice(4 * i, buf.length));
        const d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for (let j = 0; j < 8; j++) {
            const a = Utilities.int16((d >> (4 * j)) & 0x3);
            const b = Utilities.int16((d >> (4 * j + KyberService.paramsETAK768K1024)) & 0x3);
            r[8 * i + j] = a - b;
        }
    }
    return r;
}

/**
 * Returns a 24-bit unsigned integer as a long from byte x
 *
 * @param x
 * @return
 */
function convertByteTo24BitUnsignedInt(x: Buffer): number {
    return Utilities.int32(x[0] & 0xFF)
        | (Utilities.int32(x[1] & 0xFF) << 8)
        | (Utilities.int32(x[2] & 0xFF) << 16);
}

/**
 * Returns a 24-bit unsigned integer as a long from byte x
 *
 * @param x
 * @return
 */
function convertByteTo32BitUnsignedInt(x: Buffer): number {
    return Utilities.int32(x[0] & 0xFF)
        | (Utilities.int32(x[1] & 0xFF) << 8)
        | (Utilities.int32(x[2] & 0xFF) << 16)
        | Utilities.int32(Utilities.int32(x[3] & 0xFF) << 24);
}

/**
 * Computes a Barrett reduction given a 16 Bit Integer
 *
 * @param a
 * @return
 */
export function barrettReduce(a: number): number {
    const shift = Utilities.int32(1 << 26);
    const v = +Utilities.int16((shift + KyberService.paramsQ / 2) / KyberService.paramsQ).toFixed(0);
    const t = Utilities.int16(Utilities.int16((v * a) >> 26) * KyberService.paramsQ);
    return a - t;
}

/**
 * Multiply the given shorts and then run a Montgomery reduce
 *
 * @param a
 * @param b
 * @return
 */
export function modQMulMont(a: number, b: number): number {
    return montgomeryReduce(a * b);
}

/**
 * Computes a Montgomery reduction given a 32 Bit Integer
 *
 * @param a
 * @return
 */
export function montgomeryReduce(a: number): number {
    const u = Utilities.int16(Utilities.uint16(a) * KyberService.paramsQinv);
    const t = (a - u * KyberService.paramsQ) >> 16;
    return Utilities.int16(t);
}
