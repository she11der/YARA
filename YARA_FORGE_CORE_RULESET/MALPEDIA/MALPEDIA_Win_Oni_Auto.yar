rule MALPEDIA_Win_Oni_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ffe7d6a1-e7f2-579d-b056-7e9412d8f38a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oni"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.oni_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "ef51460421d5bc54251bcf8ac5edcdde6a15b31e2116a2189b470d64d9b9ae34"
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
		$sequence_0 = { 50 8d4db0 c645b000 e8???????? 8b0d???????? b8abaaaa2a 8b3d???????? }
		$sequence_1 = { 83f904 0f828d000000 83f923 0f8789000000 8bc8 }
		$sequence_2 = { ff75ec 51 ff36 8b55e8 8bcb e8???????? 83c410 }
		$sequence_3 = { 7f07 3bc7 0f4fd8 8bfb 6aff 8d4701 }
		$sequence_4 = { 3a45ec 753e 8b45f0 8b048590884300 }
		$sequence_5 = { 8d0dc0254300 ba1b000000 e9???????? a900000080 }
		$sequence_6 = { 660fd685c8feffff 33ff 6800010000 899dc8feffff 89bdccfeffff 899dd0feffff ff15???????? }
		$sequence_7 = { 8901 0fb602 5f 5e 5b 8b4c2430 33cc }
		$sequence_8 = { 8b542428 8b442414 85f6 0f8422ffffff }
		$sequence_9 = { f6c104 7519 f6c102 8d4df8 7540 eb6a }

	condition:
		7 of them and filesize <499712
}
