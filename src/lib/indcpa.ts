import { Buffer } from "buffer";
import { randomIntUpTo, uint16 } from "./utilities";
import { SHA3, SHAKE } from "sha3";
import { Poly } from "./poly";
import { KyberService } from "../services/kyber.service";

export class Indcpa {
    public poly: Poly;

    constructor(public paramsK: number) {
        this.poly = new Poly(this.paramsK);
    }

    /**
     * Generates public and private keys for the CPA-secure public-key
     * encryption scheme underlying Kyber.
     */
    public indcpaKeyGen(): [number[], number[]] {
        const rnd = Buffer.alloc(KyberService.paramsSymBytes);
        for (let i = 0; i < KyberService.paramsSymBytes; i++) {
            rnd[i] = randomIntUpTo(256);
        }

        const seed = new SHA3(512).update(rnd).digest();
        const publicSeedBuffer = seed.slice(0, KyberService.paramsSymBytes);
        const noiseSeedBuffer = seed.slice(KyberService.paramsSymBytes, KyberService.paramsSymBytes * 2);
        const publicSeed = [...publicSeedBuffer];
        const noiseSeed = [...noiseSeedBuffer];

        // generate public matrix A (already in NTT form)
        const a = this.generateMatrix(publicSeed, false);
        const s = new Array<number[]>(this.paramsK);
        const e = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            s[i] = this.poly.getNoisePoly(noiseSeed, i, this.paramsK);
            e[i] = this.poly.getNoisePoly(noiseSeed, (i + this.paramsK), this.paramsK);
            s[i] = this.poly.ntt(s[i]);
            e[i] = this.poly.ntt(e[i]);
            s[i] = this.poly.polyReduce(s[i]);
        }

        const pk = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            pk[i] = this.poly.polyToMont(this.poly.polyVectorPointWiseAccMont(a[i], s));
            pk[i] = this.poly.polyAdd(pk[i], e[i]);
            pk[i] = this.poly.polyReduce(pk[i]);
        }

        // ENCODE KEYS
        const publicKey = [];
        for (let i = 0; i < this.paramsK; i++) {
            const bytes = this.poly.polyToBytes(pk[i]);
            publicKey.push(...bytes);
        }
        publicKey.push(...publicSeed);

        const privateKey = [];
        for (let i = 0; i < this.paramsK; i++) {
            const bytes = this.poly.polyToBytes(s[i]);
            privateKey.push(...bytes);
        }
        return [publicKey, privateKey];
    }

    /**
     * Encrypt the given message using the Kyber public-key encryption scheme
     *
     * @param publicKey
     * @param message
     * @param coins
     * @return
     */
    public indcpaEncrypt(publicKey: number[], message: number[], coins: number[]): number[] {
        const pk = new Array<number[]>(this.paramsK);
        const k = this.poly.polyFromData(message);
        for (let i = 0; i < this.paramsK; i++) {
            const start = i * KyberService.paramsPolyBytes;
            const end = (i + 1) * KyberService.paramsPolyBytes;
            pk[i] = this.poly.polyFromBytes(publicKey.slice(start, end));
        }

        let seed;
        if (this.paramsK === 2) {
            seed = publicKey.slice(KyberService.paramsPolyvecBytesK512, KyberService.paramsIndcpaPublicKeyBytesK512);
        } else if (this.paramsK === 3) {
            seed = publicKey.slice(KyberService.paramsPolyvecBytesK768, KyberService.paramsIndcpaPublicKeyBytesK768);
        } else {
            seed = publicKey.slice(KyberService.paramsPolyvecBytesK1024, KyberService.paramsIndcpaPublicKeyBytesK1024);
        }

        const at = this.generateMatrix(seed, true);
        const sp = new Array<number[]>(this.paramsK);
        const ep = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.getNoisePoly(coins, i, this.paramsK);
            ep[i] = this.poly.getNoisePoly(coins, i + this.paramsK, 3);
            sp[i] = this.poly.ntt(sp[i]);
            sp[i] = this.poly.polyReduce(sp[i]);
        }

        let bp = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            bp[i] = this.poly.polyVectorPointWiseAccMont(at[i], sp);
        }
        bp = this.poly.polyVectorInvNTTMont(bp);
        bp = this.poly.polyVectorAdd(bp, ep);
        bp = this.poly.polyVectorReduce(bp);

        const epp = this.poly.getNoisePoly(coins, this.paramsK * 2, 3);
        let v = this.poly.polyVectorPointWiseAccMont(pk, sp);
        v = this.poly.invNTT(v);
        v = this.poly.polyAdd(v, epp);
        v = this.poly.polyAdd(v, k);
        v = this.poly.polyReduce(v);

        const bCompress = this.poly.compressPolyVector(bp);
        const vCompress = this.poly.compressPoly(v);

        return [...bCompress, ...vCompress];
    }

    /**
     * Decrypt the given byte array using the Kyber public-key encryption scheme
     *
     * @param packedCipherText
     * @param privateKey
     * @return
     */
    public indcpaDecrypt(packedCipherText: number[], privateKey: number[]): number[] {
        let bpEndIndex: number;
        let vEndIndex: number;
        if (this.paramsK === 2) {
            bpEndIndex = KyberService.paramsPolyvecCompressedBytesK512;
            vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK512;
        } else if (this.paramsK === 3) {
            bpEndIndex = KyberService.paramsPolyvecCompressedBytesK768;
            vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK768;
        } else {
            bpEndIndex = KyberService.paramsPolyvecCompressedBytesK1024;
            vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK1024;
        }

        let bp = this.poly.decompressPolyVector(packedCipherText.slice(0, bpEndIndex));
        bp = this.poly.polyVectorNTT(bp);

        const v = this.poly.decompressPoly(packedCipherText.slice(bpEndIndex, vEndIndex));
        const privateKeyPolyvec = this.poly.polyVectorFromBytes(privateKey);

        let mp = this.poly.polyVectorPointWiseAccMont(privateKeyPolyvec, bp);
        mp = this.poly.invNTT(mp);
        mp = this.poly.subtract(v, mp);
        mp = this.poly.polyReduce(mp);
        return this.poly.polyToMsg(mp);
    }

    /**
     * Generate a polynomial vector matrix from the given seed
     *
     * @param seed
     * @param transposed
     * @return
     */
    public generateMatrix(seed: number[], transposed: boolean): number[][][] {
        let a = new Array<number[][]>(this.paramsK);
        const xof = new SHAKE(128);
        let ctr = 0;

        for (let i = 0; i < this.paramsK; i++) {
            a[i] = new Array(this.paramsK);
            for (let j = 0; j < this.paramsK; j++) {
                const transpose = transposed ? [i, j] : [j, i];

                // obtain xof of (seed+i+j) or (seed+j+i) depending on above code
                // output is 672 bytes in length
                const outputString = xof.reset()
                    .update(Buffer.from(seed))
                    .update(Buffer.from(transpose))
                    .digest({ format: "binary", buffer: Buffer.alloc(672) });
                let output = Buffer.alloc(outputString.length).fill(outputString);
                // run rejection sampling on the output from above
                let outputlen = 3 * 168;

                // `a[i][j]` is the result here is an NTT-representation
                // `ctr` keeps track of index of output array from sampling function
                [a[i][j], ctr] = this.generateUniform(output.slice(0, 504), outputlen, KyberService.paramsN);

                while (ctr < KyberService.paramsN) { // if the polynomial hasnt been filled yet with mod q entries
                    const outputn = output.slice(504, 672); // take last 168 bytes of byte array from xof
                    // `missing` here is additional mod q polynomial coefficients
                    // `ctrn` how many coefficients were accepted and are in the output
                    const [missing, ctrn] = this.generateUniform(outputn, 168, KyberService.paramsN - ctr); // run sampling function again
                    // starting at last position of output array from first sampling function until 256 is reached
                    for (let k = ctr; k < KyberService.paramsN; k++) {
                        a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
                    }
                    ctr += ctrn;
                }
            }
        }
        return a;
    }

    /**
     * Runs rejection sampling on uniform random bytes to generate uniform
     * random integers modulo `Q`
     *
     * @param buf
     * @param bufl
     * @param len
     * @return
     */
    public generateUniform(buf: Buffer, bufl: number, len: number): [number[], number] {
        const uniformR = new Array(KyberService.paramsPolyBytes);
        let j = 0;
        let uniformI = 0;

        while ((uniformI < len) && ((j + 3) <= bufl)) {
            const d1 = (uint16((buf[j]) >> 0) | (uint16(buf[j + 1]) << 8)) & 0xFFF;
            const d2 = (uint16((buf[j + 1]) >> 4) | (uint16(buf[j + 2]) << 4)) & 0xFFF;
            j += 3;

            if (d1 < KyberService.paramsQ) {
                uniformR[uniformI] = d1;
                uniformI++;
            }
            if (uniformI < len && d2 < KyberService.paramsQ) {
                uniformR[uniformI] = d2;
                uniformI++;
            }
        }

        return [uniformR, uniformI];
    }
}
