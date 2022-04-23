import * as url from 'url';
import * as crypto from 'crypto';
import * as util from 'util';

import * as vscode from 'vscode';
import * as otplib from 'otplib';
import * as otplibCore from '@otplib/core';

const randomBytes = util.promisify(crypto.randomBytes);

interface EncryptedData {
	cipherText: string
	iv: string
	authTag: string
}

class KeyCipher {
	private masterKey: string;

	/**
	 * @param masterKey the master key for secret encryption, should be hex string.
	 */
	constructor(masterKey: string) {
		this.masterKey = masterKey;
	}

	async encrypt(plainText: string): Promise<EncryptedData> {
		const iv = await randomBytes(12);
		const masterKey = Buffer.from(this.masterKey, 'hex');

		const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
		const cipherText = Buffer.concat([
			cipher.update(plainText, 'utf8'),
			cipher.final(),
		]).toString('hex');

		return {
			cipherText: cipherText,
			iv: iv.toString('hex'),
			authTag: cipher.getAuthTag().toString('hex'),
		};
	}

	async decrypt(data: EncryptedData): Promise<string> {
		const iv = Buffer.from(data.iv, 'hex');
		const masterKey = Buffer.from(this.masterKey, 'hex');

		const cipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
		cipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
		const plainText = Buffer.concat([
			cipher.update(data.cipherText, 'hex'),
			cipher.final(),
		]).toString('utf8');
		
		return plainText;
	}
}

async function initializeMasterKey(secrets: vscode.SecretStorage): Promise<string> {
	const keyLabel = 'otp-toolbox-master-key';

	let masterKey = await secrets.get(keyLabel);
	if (masterKey === undefined) {
		const rawKey = await randomBytes(32);
		masterKey = rawKey.toString('hex');
		await secrets.store(keyLabel, masterKey);
	}

	return masterKey;
}

export async function activate(context: vscode.ExtensionContext) {

	const masterKey = await initializeMasterKey(context.secrets);
	const keyCipher = new KeyCipher(masterKey);

	context.subscriptions.push(vscode.commands.registerCommand('otp-toolbox.addKey', async () => {
		const otpUriStr = await vscode.window.showInputBox({
			title: 'Add the OTP secret',
			prompt: 'Give the URI content',
			placeHolder: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
		});
		if (otpUriStr === undefined) {
			return;
		}

		const otpRecord = parseOtpUri(otpUriStr);
		const encryptedSecret = await keyCipher.encrypt(otpRecord.secret);
		const encryptedOtpRecord = {
			type: otpRecord.type,
			common: otpRecord.common,
			encryptedSecret: encryptedSecret,
		};

		const label = `${otpRecord.common.issuer}:${otpRecord.common.account}`;
		context.globalState.update(label, encryptedOtpRecord);
		vscode.window.showInformationMessage(`${label} has been added to the secret storage.`);
	}));

	context.subscriptions.push(vscode.commands.registerCommand('otp-toolbox.clearKeys', async () => {
		const labels = context.globalState.keys();

		for (const label of labels) {
			// There is no dedicated API to remove record.
			context.globalState.update(label, undefined);
		}

		vscode.window.showInformationMessage(`All stored keys have been removed.`);
	}));

	context.subscriptions.push(vscode.commands.registerCommand('otp-toolbox.getToken', async () => {
		const labels = context.globalState.keys();
		if (labels.length === 0) {
			vscode.window.showInformationMessage('No OTP key is stored already. Use Add Key command.');
			return;
		}

		const label = await vscode.window.showQuickPick(labels, {
			title: "Pick from registered OTP Keys"
		});
		if (label === undefined) {
			return;
		}

		const encryptedOtpRecord: EncryptedOtpRecord | undefined = context.globalState.get(label);
		if (encryptedOtpRecord === undefined) {
			return;
		}
		const secret = await keyCipher.decrypt(encryptedOtpRecord.encryptedSecret);
		const otpRecord: OtpRecord = {
			type: encryptedOtpRecord.type,
			common: encryptedOtpRecord.common,
			secret: secret,
		};

		const token = generateToken(otpRecord);
		await vscode.env.clipboard.writeText(token);
		vscode.window.showInformationMessage(`"${token}" is sent to the clipboard.`);
	}));

	context.subscriptions.push(vscode.commands.registerCommand('otp-toolbox.debug', async () => {
		const otpUriStr = await vscode.window.showInputBox({
			prompt: 'Give the URI content',
			placeHolder: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
			value: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
		});
		if (otpUriStr === undefined) {
			return;
		}

		const token = generateTokenFromUri(otpUriStr);
		vscode.window.showInformationMessage(`${token}`);
	}));
}

export async function deactivate() {}

interface OtpRecord {
	type: string;
	common: OtpRecordCommon;
	secret: string;
}

interface EncryptedOtpRecord {
	type: string;
	common: OtpRecordCommon;
	encryptedSecret: EncryptedData;
}

interface OtpRecordCommon {
	issuer: string;
	account: string;
	digits: number;
	counter: number;
	period: number;
	algorithm: string;
}

function generateTokenFromUri(otpUriStr:string): string {
	const otpRecord = parseOtpUri(otpUriStr);

	const tool = otplib.authenticator;
	const password = tool.generate(otpRecord.secret);

	return password;
}

function generateToken(record: OtpRecord): string {

	const algorithm = parseAlgorithm(record.common.algorithm);

	const tool = otplib.authenticator;
	tool.resetOptions();
	tool.options = {
		algorithm: algorithm,
		digits: record.common.digits,
		step: record.common.period,

	};
	const password = tool.generate(record.secret);

	return password;
}

function parseAlgorithm(algorithm: string): otplibCore.HashAlgorithms {
	switch (algorithm.toLowerCase()) {
		case otplibCore.HashAlgorithms.SHA1:
			return otplibCore.HashAlgorithms.SHA1;
		case otplibCore.HashAlgorithms.SHA256:
			return otplibCore.HashAlgorithms.SHA256;
		case otplibCore.HashAlgorithms.SHA512:
			return otplibCore.HashAlgorithms.SHA512;
		default:
			throw new Error(`unsupported algorithm ${algorithm}`);
	}
}

function parseOtpUri(otpUriStr: string): OtpRecord {
	const otpUri = new url.URL(otpUriStr);

	const schema = otpUri.protocol;
	if (schema !== 'otpauth:') {
		throw new Error(`wrong schema: ${schema}`);
	}
	const type = otpUri.host;
	const label = otpUri.pathname.substring(1);

	const secret = otpUri.searchParams.get('secret');
	if (secret === null) {
		throw new Error('no secret given in the URI');
	}

	let issuer: string = '';
	let account: string = '';
	let algorithm: string = 'SHA1';
	let digits: number = 6;
	let counter: number = 0;
	let period: number = 30;

	const tokens = label.split(':');
	if (tokens.length === 2) {
		issuer = tokens[0];
		account = tokens[1];
	} else {
		account = tokens[1];
	}

	const issuerQuery = otpUri.searchParams.get('issuer');
	if (issuerQuery !== null) {
		issuer = issuerQuery;
	}
	const digitsQuery = otpUri.searchParams.get('digits');
	if (digitsQuery !== null) {
		digits = parseInt(digitsQuery);
	}
	const counterQuery = otpUri.searchParams.get('counter');
	if (counterQuery !== null) {
		counter = parseInt(counterQuery);
	}
	const periodQuery = otpUri.searchParams.get('period');
	if (periodQuery !== null) {
		period = parseInt(periodQuery);
	}

	return {
		type: type,
		common: {
			issuer: issuer,
			account: account,
			algorithm: algorithm,
			digits: digits,
			counter: counter,
			period: period,
		},
		secret: secret,
	};
}
