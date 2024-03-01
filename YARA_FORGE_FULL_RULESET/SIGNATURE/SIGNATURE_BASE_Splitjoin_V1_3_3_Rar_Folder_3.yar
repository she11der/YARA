import "pe"

rule SIGNATURE_BASE_Splitjoin_V1_3_3_Rar_Folder_3
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4ffd7501-339c-52b7-8661-2c3ca57dfa1f"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2478-L2493"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
		logic_hash = "79eb49413cd6919e4b91e916d2612e007fd2c4da7244d9e1e3dd04d46c461d8c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "ie686@sohu.com" fullword ascii
		$s3 = "splitjoin.exe" fullword ascii
		$s7 = "SplitJoin" fullword ascii

	condition:
		all of them
}
