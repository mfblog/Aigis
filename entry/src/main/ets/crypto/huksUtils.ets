import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { huks } from '@kit.UniversalKeystoreKit';
import { MasterKeyInfo } from '../common/schema';
import { getRandomInt } from '../common/utils';

type ParamsPurpose = Array<huks.HuksParam>;
const PARAMS_PURPOSE_DERIVE: ParamsPurpose = [
    {tag: huks.HuksTag.HUKS_TAG_PURPOSE,   value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DERIVE},
    {tag: huks.HuksTag.HUKS_TAG_DIGEST,    value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256},
    {tag: huks.HuksTag.HUKS_TAG_KEY_SIZE,  value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256},
];

const PARAMS_IN_HUKS: Array<huks.HuksParam> = [{
    tag:   huks.HuksTag.HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
    value: huks.HuksKeyStorageType.HUKS_STORAGE_ONLY_USED_IN_HUKS,
}];
const PARAMS_EXPORT_ALL: Array<huks.HuksParam> = [{
    tag:   huks.HuksTag.HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
    value: huks.HuksKeyStorageType.HUKS_STORAGE_KEY_EXPORT_ALLOWED,
}];

async function generateRandomSecret(length: number = 32): Promise<Uint8Array> {
    const rand = cryptoFramework.createRandom();
    const data = await rand.generateRandom(length);
    return data.data;
}

async function generateRandomSalt24(): Promise<Uint8Array> {
    const rand = cryptoFramework.createRandom();
    const data = await rand.generateRandom(24);
    return Uint8Array.from(
        Array.from(data.data)
            .map(x => (x % 36).toString(36))
            .map(x => x.charCodeAt(0))
    );
}

class HUKSAgent {
    private props: Array<huks.HuksParam> = [];

    constructor() {}

    with(params: Array<huks.HuksParam>) {
        this.props.concat(params);
        return this;
    }

    async generateKeyItem(keyAlias: string, purpose: ParamsPurpose, _exported: boolean = false): Promise<string|undefined> {
        this.with(purpose).with(PARAMS_IN_HUKS);
        const huksOptions: huks.HuksOptions = {
            properties: this.props,
            inData: new Uint8Array(new Array())
        };
        //
        try {
            await huks.generateKeyItem(keyAlias, huksOptions);
            return keyAlias;
        } catch (err) {
            console.error(`promise: generateKeyItem failed, ${JSON.stringify(err)}`);
            return undefined;
        }
    }

    async importKeyItem(keyAlias: string, purpose: ParamsPurpose, plaintext: Uint8Array): Promise<string|undefined> {
        this.with(purpose);
        const huksOptions: huks.HuksOptions = {
            properties: this.props,
            inData: plaintext,
        };
        try {
            await huks.importKeyItem(keyAlias, huksOptions);
            return keyAlias;
        } catch (err) {
            console.error(`promise: generateKeyItem failed, ${JSON.stringify(err)}`);
            return undefined;
        }
    }

    async deriveKeyItem(srcKeyAlias: string, salt: Uint8Array, iteration: number, outKeyAlias: string): Promise<void> {

    }
}

export async function generateMasterKeyInHUKS(keyAlias: string, password: string): Promise<MasterKeyInfo> {
    const secret = await generateRandomSecret(32);
    const importAgent = new HUKSAgent();
    await importAgent.importKeyItem(keyAlias, PARAMS_PURPOSE_DERIVE, secret);
    //
    const type = 'PBKDF2';
    const kdfAgent = new HUKSAgent();
    const salt = await generateRandomSalt24();
    const iteration = getRandomInt(1000, 10000);
    await kdfAgent.deriveKeyItem(keyAlias, salt, iteration, keyAlias);
    //
    return { type, keyAlias, secret, salt, iteration };
}
