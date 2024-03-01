rule SIGNATURE_BASE_Aspx_Shell : FILE
{
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "d4287007-79af-59fa-b8c8-3ac08d75b3bd"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L122-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		logic_hash = "b31c36f53d46e17b6d97e582e46c540928a386e2075b841f5c11b959a0c68462"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii

	condition:
		filesize <20KB and all of them
}
