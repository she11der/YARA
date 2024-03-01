rule TRELLIX_ARC_Nemty_Ransomware_2_6 : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Nemty Ransomware version 2.6"
		author = "Marc Rivero | McAfee ATR Team"
		id = "335dff33-d078-58ba-b68b-a949895b710f"
		date = "2020-04-06"
		modified = "2020-08-14"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Nemty.yar#L47-L80"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "52b7d20d358d1774a360bb3897a889e14d416c3b2dff26156a506ff199c3388d"
		logic_hash = "dacf709838ef2ef65d25bdbbd92007ab46a95953031d7bee75eac046f670171a"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Nemty"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pattern = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????A1????????33??89????8B????578D??????????89??????????E8????????33??6A??5839????76??5683????75??508D????5350E8????????8D??????????508D????E8????????83????6A??5880??????75??C6??????4879??EB??FE????33??8A??????8B??????????30????47403B????72??5E8B????33??5FE8????????C9C3558B??51515333??5633??32??89????39????0F86????????578B????8B????8A????8B??83????74??4F74??4F75??21????0FB6??0FB6??83????8B??C1????C1????0B??8A??????????83????88????8A??????????8B????88??????83????EB??0FB6??0FB6??83????6A??C1????C1????5E0B??EB??33??0FB6??46C1????8A??????????88????40FF????8A??8B????3B????72??5F4E74??4E75??0FB6??83????8A????????????88????C6????????83????EB??0FB6??83????C1????8A??????????88????66????????????83????5EC6??????5BC9C3558B??33??F6??????75??5733??39????76??8B????8A????80????74??80????7C??80????7F??0FB6??8A??????????80????74??8B??83????83????74??4A74??4A74??4A75??08????40EB??8A??C0????80????08????40C0????EB??8A??C0????80????08????40C0????EB??C0????88????473B????72??EB??33??5F5DC3558B??518B??85??74??8B????568B??89????3B??74??576A??33??E8????????83????3B????75??5FFF??E8????????595E33??89??89????89????C9C3558B??80??????74??83??????72??538B??85??74??575356E8????????83????53E8????????595BC7????????????89????C6??????5DC2????C7??????????E9????????558B??568B??C7??????????E8????????F6??????74??56E8????????598B??5E5DC2????558B??83????81??????????A1????????33??89????????????5356578D????508D??????E8????????68????????8D????????????E8????????6A??5F33??83????66????????8D????8B??33??5089??????89??????E8????????E8????????33??66????????8B????????????03??????83????8D??????89??????89??????E8????????538D??????5083????8D??????E8????????538D????????????5083????E8????????8B??8D??????E8????????6A??33??E8????????83????????8B??????73??8D??????8D????????????5150FF??????????89??????83????0F84????????8B??????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????F6??????????????8D????????????508D??????8D??????74??E8????????598D??????51E8????????8B??598D??????E8????????6A??33??8D??????E8????????6A??8D??????E8????????83????8D??????8B??50E8????????E8????????83????E9????????E8????????8B??598D??????E8????????6A??33??8D??????E8????????8D????????????50FF??????????508D??????E8????????8B??????6A??5F39??????73??8D??????8B??????????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??74??8B??????39??????73??8D??????68????????50FF??85??74??83????8B??68????????E8????????83????8D????????????8B??51E8????????E8????????83????85??75??8B??????39??????73??8D??????83????8B??51E8????????E8????????83????6A??33??8D??????E8????????8D????????????50FF??????FF??????????85??0F85????????FF??????FF??????????33??435333??8D?????? }

	condition:
		uint16(0)==0x5a4d and filesize <1500KB and $pattern
}
