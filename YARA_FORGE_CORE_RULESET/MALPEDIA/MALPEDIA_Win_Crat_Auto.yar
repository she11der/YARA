rule MALPEDIA_Win_Crat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5ca84b15-9c50-5146-aeb0-8e43c37e0140"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.crat_auto.yar#L1-L175"
		license_url = "N/A"
		logic_hash = "a19b8917ee2e01478bdd8090b22583a65c2cc48e63af4151406da25e5b4c7a8a"
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
		$sequence_0 = { e8???????? 488bd0 488d8d90010000 e8???????? 90 }
		$sequence_1 = { e8???????? 488bd0 488d8d88000000 e8???????? 90 }
		$sequence_2 = { 7406 e8???????? 90 488b542420 4883c2e8 }
		$sequence_3 = { e8???????? 488bc8 4885c0 7433 }
		$sequence_4 = { e8???????? 488bd0 488d8da8010000 e8???????? 90 }
		$sequence_5 = { 48f7c20000ffff 7523 0fb7fa 8bcf e8???????? 4885c0 7427 }
		$sequence_6 = { e8???????? 488bd0 488d4d58 e8???????? 90 }
		$sequence_7 = { ebd0 498bc4 48833d????????10 480f4305???????? 482bc8 }
		$sequence_8 = { 33d2 c1e902 f7f1 eb02 }
		$sequence_9 = { ffd0 85c0 750f ff15???????? }
		$sequence_10 = { 8bcb e8???????? 8b55d8 8b4b0c }
		$sequence_11 = { 8bcb e8???????? 8b4b0c 8d4101 }
		$sequence_12 = { 8b4004 8bca 3bc2 0f47c8 51 8b4d10 e8???????? }
		$sequence_13 = { 8b4b0c 8d4101 89430c c60100 8b4dd4 41 }
		$sequence_14 = { 8b4324 668948fe c740f800000000 c740f400000000 c740f000000000 5f 5e }
		$sequence_15 = { 8b5508 0f57c0 56 8b750c b896000000 f30f7f01 }
		$sequence_16 = { 8b4b0c 8d4101 89430c 8a45d3 8801 8b4dd4 41 }

	condition:
		7 of them and filesize <4161536
}
