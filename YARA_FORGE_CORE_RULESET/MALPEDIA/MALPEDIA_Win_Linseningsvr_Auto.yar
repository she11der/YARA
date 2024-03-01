rule MALPEDIA_Win_Linseningsvr_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "acba9094-ad6f-5dc3-983b-34f0b25c68ba"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.linseningsvr"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.linseningsvr_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "2644e1e1ca2803e3e5ff6eb23f753be414d9d9a67fa2dca1bfd8c0b76cd44619"
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
		$sequence_0 = { 81c4cc0d0000 c3 68ffffff7f 56 ff15???????? 83f8ff }
		$sequence_1 = { 5d b801000000 5b 81c4cc0d0000 }
		$sequence_2 = { 8b4c2428 6a24 8d542464 6a01 52 89442464 }
		$sequence_3 = { 7e16 8b742414 8bd1 8d7c1f18 c1e902 f3a5 8bca }
		$sequence_4 = { f6c202 7410 8088????????20 8a9405ecfcffff ebe3 80a0808b400000 40 }
		$sequence_5 = { 0f858b030000 33c9 8acc 3ac8 }
		$sequence_6 = { 55 6800010000 8d942464040000 6a01 52 e8???????? }
		$sequence_7 = { 8acc 3ac8 0f857f030000 33d2 55 89542432 }
		$sequence_8 = { 66895c2411 89442419 885c2418 8944241d 89442421 6689442425 88442427 }
		$sequence_9 = { 7514 ff15???????? 50 68???????? e8???????? 83c408 55 }

	condition:
		7 of them and filesize <81360
}
