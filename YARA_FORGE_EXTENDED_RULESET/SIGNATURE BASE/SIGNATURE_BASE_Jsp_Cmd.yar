rule SIGNATURE_BASE_Jsp_Cmd : FILE
{
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		author = "Florian Roth (Nextron Systems)"
		id = "74db62b8-82d5-5a34-aa72-2f85053715a4"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L209-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
		logic_hash = "ab5b013a385549322bcb2811fa1a2d14b5633e2c41b9486b1e1c50c02437b8e6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii
		$s3 = "WEB-INF/web.xmlPK" fullword ascii
		$s4 = "META-INF/MANIFEST.MF" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <2KB and all of them
}
