import datetime


def datetime_from_u64(u64):
    micro_secs, _ = divmod(u64, 10)
    time_delta = datetime.timedelta(
        microseconds=micro_secs
    )

    orig_datetime = datetime.datetime(1601, 1, 1)
    new_datetime = orig_datetime + time_delta

    return new_datetime
