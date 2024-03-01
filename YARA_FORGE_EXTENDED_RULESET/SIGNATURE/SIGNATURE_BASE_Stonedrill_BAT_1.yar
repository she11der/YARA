import "pe"
import "math"

rule SIGNATURE_BASE_Stonedrill_BAT_1 : FILE
{
	meta:
		description = "Rule to detect Batch file from StoneDrill report"
		author = "Florian Roth (Nextron Systems)"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_stonedrill.yar#L65-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d7263a527cae45072082c0f2fd0abc33acb2a25b34c06becf36fbd36f0697d5c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "set u100=" ascii
		$s2 = "set u200=service" ascii fullword
		$s3 = "set u800=%~dp0" ascii fullword
		$s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
		$s5 = "%\" start /b %systemroot%\\system32\\%" ascii

	condition:
		uint32(0)==0x68636540 and 2 of them and filesize <500
}
