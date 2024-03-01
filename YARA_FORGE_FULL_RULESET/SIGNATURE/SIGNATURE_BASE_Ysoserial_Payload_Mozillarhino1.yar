rule SIGNATURE_BASE_Ysoserial_Payload_Mozillarhino1 : FILE
{
	meta:
		description = "Ysoserial Payloads - file MozillaRhino1.bin"
		author = "Florian Roth (Nextron Systems)"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://github.com/frohoff/ysoserial"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_ysoserial_payloads.yar#L10-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ca8cdd2781812ed373ca558b3a5a2fac5d236e16e6dbb8d66caa45081aef968b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"

	strings:
		$s3 = "ysoserial.payloads" fullword ascii

	condition:
		( uint16(0)==0xedac and filesize <40KB and all of them )
}
