import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Matryoshka_Injector : FILE
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "e4cf2a31-33c8-5db1-84ca-f63b65a0a0a3"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_wilted_tulip.yar#L167-L189"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e02d26882c85b77bd97629fce20bd027e1f5f7e28ae0c43c9ea7a4b1e5d02cd1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
		hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"

	strings:
		$s1 = "Injector.dll" fullword ascii
		$s2 = "ReflectiveLoader" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them ) or (pe.exports("__dec") and pe.exports("_check") and pe.exports("_dec") and pe.exports("start") and pe.exports("test"))
}
