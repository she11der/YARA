import "pe"

rule SIGNATURE_BASE_Pscan_Portscan_1
{
	meta:
		description = "PScan - Port Scanner"
		author = "F. Roth"
		id = "54997776-644b-5a72-b08c-7174b7dc7f66"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L74-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c624fcdf28506b551bf7b36883d95b279a7c56322337a0acafd91205659c92cc"
		score = 50
		quality = 85
		tags = ""

	strings:
		$a = "00050;0F0M0X0a0v0}0"
		$b = "vwgvwgvP76"
		$c = "Pr0PhOFyP"

	condition:
		all of them
}
