rule SIGNATURE_BASE_SUSP_LNK_File_Pathtraversal : FILE
{
	meta:
		description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
		author = "Florian Roth (Nextron Systems)"
		id = "f4f6709f-9c4d-5f0c-9826-97444d282adc"
		date = "2018-05-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L170-L186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9935c454518abe7fd4ec4f09e36e4200ec7c9f3b3ad004e9b49d60c08f508236"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "..\\..\\..\\..\\..\\"

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and ( filesize <1KB and all of them )
}
