import "pe"

rule ESET_Facebook_Bot : FILE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "643b137f-af79-584c-8266-f2335a79f1ba"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/stantinko/stantinko.yar#L69-L100"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "8ea779f90fa6080398403e3e6f9d342360c35e93c756ed43cb699f090106504e"
		score = 75
		quality = 55
		tags = "FILE"
		Author = "Frédéric Vachon"
		Description = "Stantinko's Facebook bot"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "m_upload_pic&return_uri=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
		$s2 = "D:\\work\\brut\\cms\\facebook\\facebookbot\\Release\\facebookbot.pdb" fullword ascii
		$s3 = "https%3A%2F%2Fm.facebook.com%2Fcomment%2Freplies%2F%3Fctoken%3D" fullword ascii
		$s4 = "reg_fb_gate=https%3A%2F%2Fm.facebook.com%2Freg" fullword ascii
		$s5 = "reg_fb_ref=https%3A%2F%2Fm.facebook.com%2Freg%2F" fullword ascii
		$s6 = "&return_uri_error=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
		$x1 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword ascii
		$x2 = "registration@facebookmail.com" fullword ascii
		$x3 = "https://m.facebook.com/profile.php?mds=" fullword ascii
		$x4 = "https://upload.facebook.com/_mupload_/composer/?profile&domain=" fullword ascii
		$x5 = "http://staticxx.facebook.com/connect/xd_arbiter.php?version=42#cb=ff43b202c" fullword ascii
		$x6 = "https://upload.facebook.com/_mupload_/photo/x/saveunpublished/" fullword ascii
		$x7 = "m.facebook.com&ref=m_upload_pic&waterfall_source=" fullword ascii
		$x8 = "payload.commentID" fullword ascii
		$x9 = "profile.login" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (1 of ($s*) or 3 of ($x*))) or ( all of them )
}
