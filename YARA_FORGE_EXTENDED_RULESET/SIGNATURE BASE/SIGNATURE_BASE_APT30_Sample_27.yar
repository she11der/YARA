rule SIGNATURE_BASE_APT30_Sample_27 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "22815745-086f-59ee-aac1-f35e49aa5835"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L727-L746"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "959573261ca1d7e5ddcd19447475b2139ca24fe1"
		logic_hash = "5ef0661c5c04f0f0923548509363971011194a16e4308fcfdea5db90e85518a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Mozilla/4.0" fullword ascii
		$s1 = "dizhi.gif" fullword ascii
		$s5 = "oftHaveAck+" ascii
		$s10 = "HlobalAl" fullword ascii
		$s13 = "$NtRND1$" fullword ascii
		$s14 = "_NStartup" ascii
		$s16 = "GXSYSTEM" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
