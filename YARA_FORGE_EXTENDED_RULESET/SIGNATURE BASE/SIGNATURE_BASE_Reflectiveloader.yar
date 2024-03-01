import "pe"

rule SIGNATURE_BASE_Reflectiveloader : FILE
{
	meta:
		description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
		author = "Florian Roth (Nextron Systems)"
		id = "d8a601d7-b99a-59dc-bfc7-bf0e35b5d8bd"
		date = "2017-07-17"
		modified = "2021-03-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_loaders.yar#L14-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4d839674f8d8181b11af964a7c84a9eb8f07623500dd2695fca9ca3b15c247e2"
		score = 70
		quality = 85
		tags = "FILE"
		nodeepdive = 1

	strings:
		$x1 = "ReflectiveLoader" fullword ascii
		$x2 = "ReflectivLoader.dll" fullword ascii
		$x3 = "?ReflectiveLoader@@" ascii
		$x4 = "reflective_dll.x64.dll" fullword ascii
		$x5 = "reflective_dll.dll" fullword ascii
		$fp1 = "Sentinel Labs, Inc." wide
		$fp2 = "Panda Security, S.L." wide ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or pe.exports("ReflectiveLoader") or pe.exports("_ReflectiveLoader@4") or pe.exports("?ReflectiveLoader@@YGKPAX@Z")) and not 1 of ($fp*)
}
