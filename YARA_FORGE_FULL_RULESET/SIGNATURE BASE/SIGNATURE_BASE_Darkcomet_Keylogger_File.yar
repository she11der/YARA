import "pe"

rule SIGNATURE_BASE_Darkcomet_Keylogger_File : FILE
{
	meta:
		description = "Looks like a keylogger file created by DarkComet Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "65058450-3ae3-5b85-bcc5-8bc1fab14614"
		date = "2014-07-25"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3049-L3063"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "28f2eb8f5082559f9de4e72243f4bf8a0be21a9a4c5e16c443d036733584ea97"
		score = 50
		quality = 35
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/

	condition:
		uint16(0)==0x3A3A and #entry>10 and #timestamp>10
}
