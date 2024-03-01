rule SIGNATURE_BASE_FSO_S_EFSO_2
{
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "e88d324c-1dee-5b07-b528-cf760e3ee7a6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8367-L8379"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
		logic_hash = "462c713e5d4fb6d0db91b14bfacdca73f780559ba2dad80988c356ee1a3d369d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"

	condition:
		all of them
}
