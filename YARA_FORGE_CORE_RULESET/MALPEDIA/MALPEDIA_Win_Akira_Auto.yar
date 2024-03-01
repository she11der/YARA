rule MALPEDIA_Win_Akira_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5047b686-dc46-5a3e-aa74-fc92a34b0f3e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.akira"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.akira_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "c1ae7dbc4a382b6e7a49f30242c48e32f0bd119ae1ed5e26b8c812d114457836"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8b01 85c0 7e18 ffc8 8901 498b4840 488b11 }
		$sequence_1 = { 418bc9 83c902 41f6c108 410f44c9 81e13bffffff 390d???????? 741d }
		$sequence_2 = { 90 488b4b60 48894c2430 4885c9 7445 488b5370 4889542440 }
		$sequence_3 = { 7cee 488bcb 488b5c2430 4883c420 5f e9???????? 0fb6043b }
		$sequence_4 = { ff5208 90 488b4b60 48894c2430 4885c9 7445 488b5370 }
		$sequence_5 = { e8???????? 488975d0 488b4dd8 488975d8 48894808 0f1045e0 0f114010 }
		$sequence_6 = { 4488443c6e 48ffc7 4883ff0a 72ac 0f57c0 0f118590020000 0f57c9 }
		$sequence_7 = { 740a e8???????? 488bd8 eb03 498bdd 49897e18 }
		$sequence_8 = { e8???????? 33f6 41897578 49397568 744d 488b0f 40387128 }
		$sequence_9 = { c645bf01 4883ef01 75b4 0f2845bf 33ff 4c8d75cf 48837de710 }

	condition:
		7 of them and filesize <1286144
}
