import "pe"

rule ESET_IIS_Group10
{
	meta:
		description = "Detects Group 10 native IIS malware family"
		author = "ESET Research"
		id = "31368b38-9128-594d-888d-e97d3edc7a1f"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/badiis/badiis.yar#L389-L423"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "48701168d7da726222227ef757f1a4005a49c0bf300123319ce03db09445b3ef"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "IIS7.dll"
		$s2 = "<title>(.*?)title(.*?)>"
		$s3 = "<meta(.*?)name(.*?)=(.*?)keywords(.*?)>"
		$s4 = "<meta(.*?)name(.*?)=(.*?)description(.*?)>"
		$s5 = "js.breakavs.co"
		$s6 = "&#24494;&#20449;&#32676;&#45;&#36187;&#36710;&#80;&#75;&#49;&#48;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#95;&#24184;&#36816;&#39134;&#33351;&#95;&#24184;&#36816;&#50;&#56;&#32676;"
		$s7 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#112;&#107;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#32676;&#44;"
		$s8 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#21495;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;"
		$e1 = "Baiduspider"
		$e2 = "Sosospider"
		$e3 = "Sogou web spider"
		$e4 = "360Spider"
		$e5 = "YisouSpider"
		$e6 = "sogou.com"
		$e7 = "soso.com"
		$e8 = "uc.cn"
		$e9 = "baidu.com"
		$e10 = "sm.cn"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 2 of ($e*) and 3 of ($s*)
}
