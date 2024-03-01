import "math"

rule SIGNATURE_BASE_WEBSHELL_ASP_Generic_Eval_On_Input : FILE
{
	meta:
		description = "Generic ASP webshell which uses any eval/exec function directly on user input"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
		date = "2021-01-07"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L3359-L3463"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d6b96d844ac395358ee38d4524105d331af42ede"
		hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
		hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
		hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"
		logic_hash = "f7b9f43cf2fd6d08b7438f003242e9a19dcea282959c7a1fdff3a35e261a031e"
		score = 75
		quality = -199
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
		$payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
		$payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
		$payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = "<?php"
		$php2 = "<?="
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii
		$perl1 = "PerlScript" fullword

	condition:
		( filesize <1100KB and (( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and any of ($payload_and_input*)) or ( filesize <100 and any of ($payload_and_input*))
}
