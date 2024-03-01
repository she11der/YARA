import "pe"

rule SIGNATURE_BASE_Winnti_Signing_Cert : FILE
{
	meta:
		description = "Detects a signing certificate used by the Winnti APT group"
		author = "Florian Roth (Nextron Systems)"
		id = "0cf185eb-fb8d-5e1f-9089-4f36eb4798de"
		date = "2015-10-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_winnti.yar#L9-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6fd5f2808e7d683b9c4b7f5d4ccfd0eb87037eb2e70700b2c083db8c6ddf4a26"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"

	strings:
		$s1 = "Guangzhou YuanLuo Technology Co." ascii
		$s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
		$s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of them
}
