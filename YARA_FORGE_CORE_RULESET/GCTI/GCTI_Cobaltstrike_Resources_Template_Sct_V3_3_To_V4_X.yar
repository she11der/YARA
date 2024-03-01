rule GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		author = "gssincla@google.com"
		id = "9d2b1dfa-5f76-503f-9198-6ed0d039e0cb"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template_Sct_v3_3_to_v4_x.yara#L17-L38"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		logic_hash = "8868445ced4945c469764b7f311d6cb11c99cf0f2d770113e5e617e0187a962c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$scriptletstart = "<scriptlet>" nocase
		$registration = "<registration progid=" nocase
		$classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
		$scriptend = "</script>" nocase
		$antiregistration = "</registration>" nocase
		$scriptletend = "</scriptlet>"

	condition:
		all of them and @scriptletstart[1]<@registration[1] and @registration[1]<@classid[1] and @classid[1]<@scriptlang[1] and @scriptlang[1]<@cdata[1]
}
