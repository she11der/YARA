import "math"

rule SIGNATURE_BASE_WEBSHELL_In_Image : FILE
{
	meta:
		description = "Webshell in GIF, PNG or JPG"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
		date = "2021-02-27"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_webshells.yar#L6573-L6833"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
		hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
		hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
		logic_hash = "a5ed18decdad90d00ec975f0d2574a3ce80bcc60ff97b4c337c0f411c1c490e4"
		score = 55
		quality = -1167
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$png = { 89 50 4E 47 }
		$jpg = { FF D8 FF E0 }
		$gif = "GIF8" wide ascii
		$gif2 = "gif89"
		$gif3 = "Gif89"
		$mdb = { 00 01 00 00 53 74 }
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		$php_multi_write1 = "fopen(" wide ascii
		$php_multi_write2 = "fwrite(" wide ascii
		$php_write1 = "move_uploaded_file" fullword wide ascii
		$cjsp1 = "<%" ascii wide
		$cjsp2 = "<jsp:" ascii wide
		$cjsp3 = /language=[\"']java[\"\']/ ascii wide
		$cjsp4 = "/jstl/core" ascii wide
		$payload1 = "ProcessBuilder" fullword ascii wide
		$payload2 = "processCmd" fullword ascii wide
		$rt_payload1 = "Runtime" fullword ascii wide
		$rt_payload2 = "getRuntime" fullword ascii wide
		$rt_payload3 = "exec" fullword ascii wide
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
		$asp_payload0 = "eval_r" fullword nocase wide ascii
		$asp_payload1 = /\beval\s/ nocase wide ascii
		$asp_payload2 = /\beval\(/ nocase wide ascii
		$asp_payload3 = /\beval\"\"/ nocase wide ascii
		$asp_payload4 = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8 = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9 = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii
		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" nocase wide ascii
		$asp_cr_write2 = "CreateObject (" nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii

	condition:
		filesize <5MB and ($png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0) and ((((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and (( any of ($cpayload*) or all of ($m_cpayload_preg_filter*)) or ( any of ($php_write*) or all of ($php_multi_write*)))) or (( any of ($cjsp*)) and (1 of ($payload*) or all of ($rt_payload*))) or ((( any of ($tagasp_long*) or any of ($tagasp_classid*) or ($tagasp_short1 and $tagasp_short2 in ( filesize -100.. filesize )) or ($tagasp_short2 and ($tagasp_short1 in (0..1000) or $tagasp_short1 in ( filesize -1000.. filesize )))) and not (( any of ($perl*) or $php1 at 0 or $php2 at 0) or ((#jsp1+#jsp2+#jsp3)>0 and (#jsp4+#jsp5+#jsp6+#jsp7)>0))) and (( any of ($asp_payload*) or all of ($asp_multi_payload_one*) or all of ($asp_multi_payload_two*) or all of ($asp_multi_payload_three*) or all of ($asp_multi_payload_four*) or all of ($asp_multi_payload_five*)) or ( any of ($asp_always_write*) and ( any of ($asp_write_way_one*) and any of ($asp_cr_write*)) or ( any of ($asp_streamwriter*))))))
}
