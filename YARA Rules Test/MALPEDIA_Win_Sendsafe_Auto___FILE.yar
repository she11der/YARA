rule MALPEDIA_Win_Sendsafe_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cb217c22-cbf0-508f-ac96-405f94d46039"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sendsafe"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sendsafe_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "e90570bf37f8e67b125b5c0e63f782c1ecedcd1e6ef21243ea37efff8deeb91b"
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
		$sequence_0 = { ff36 f30f6f442438 8d442428 50 660fefc8 50 8b4608 }
		$sequence_1 = { f20f5e15???????? f20f59ca f20f58c1 f20f2cc8 894dd4 8b550c 83ba381c000000 }
		$sequence_2 = { e8???????? 8b8510feffff e9???????? 6800010000 8b9588feffff 52 e8???????? }
		$sequence_3 = { c1e000 8b4dfc 0fbe1401 85d2 7409 8b45f8 83c001 }
		$sequence_4 = { e8???????? 83c40c 8983b0010000 85c0 750a 6815060000 e9???????? }
		$sequence_5 = { e8???????? 83c414 85c0 0f84e1010000 ff7518 8d4704 57 }
		$sequence_6 = { eb07 c745fc00000000 8b5508 8b4204 3b45fc 7404 33c0 }
		$sequence_7 = { 8b783c 037904 8b8610010000 8bef c1f808 896c2414 8807 }
		$sequence_8 = { 8b4620 83c408 314500 8b4624 314504 8b4628 314648 }
		$sequence_9 = { eb06 8b55f4 8955f0 b801000000 6bc800 8b55f0 0fbe040a }

	condition:
		7 of them and filesize <3743744
}