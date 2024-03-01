import "pe"

rule SIGNATURE_BASE_Appinithook : FILE
{
	meta:
		description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "73713011-3083-5cdf-b59c-f4da67d2d2ab"
		date = "2015-07-15"
		modified = "2023-12-05"
		reference = "https://goo.gl/Z292v6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mimikatz.yar#L156-L176"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
		logic_hash = "a4de3a062e309715c339a45a16a7ff8f9a55851cb41097a6925fd11f649547d2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Release\\AppInitHook.pdb" ascii
		$s1 = "AppInitHook.dll" fullword ascii
		$s2 = "mimikatz.exe" fullword wide
		$s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
		$s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
		$s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
		$s6 = "VoidFunc" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 4 of them
}
