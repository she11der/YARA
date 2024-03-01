rule MALPEDIA_Win_Gsecdump_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b81c271d-e899-564d-95e1-3cec03c5f3c1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gsecdump"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gsecdump_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "6bf60f2f5adb73a31aef591a4e85eec2a9f319786a1094bc7166c02e51c8574f"
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
		$sequence_0 = { c7060f000000 c746fc00000000 c646ec00 83c61c 8d56e8 3bd7 }
		$sequence_1 = { 8b442438 50 e8???????? 83c404 8b4c2478 64890d00000000 59 }
		$sequence_2 = { 7205 e8???????? 83460401 e9???????? 8b06 83f8fe }
		$sequence_3 = { 7376 8bcf c1e105 894d14 03cb 51 50 }
		$sequence_4 = { 8d57fe 52 53 8d442430 50 8bce e8???????? }
		$sequence_5 = { 51 e8???????? 83c408 85ff 8bf7 0f869afdffff 8b4c2414 }
		$sequence_6 = { 50 8d8c24bc000000 c684244401000004 e8???????? 8d4c2428 889c2438010000 e8???????? }
		$sequence_7 = { 8b4604 3b442424 0f84a3000000 8b06 83f8fe 7427 85c0 }
		$sequence_8 = { 50 e8???????? 8b4538 3bc6 7409 50 e8???????? }
		$sequence_9 = { 33d2 59 f7f1 33f6 8d2c95908c4400 8b7d00 85ff }

	condition:
		7 of them and filesize <630784
}
