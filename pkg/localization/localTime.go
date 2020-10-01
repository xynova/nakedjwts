package localization

import (
	"time"
)

type LocalTime struct {
	time.Time
}

func NewLocalTime(tz string, resetClock bool) (*LocalTime, error){
	return createLocalTimeFrom(time.Now(), tz, resetClock)
}


func (t *LocalTime) BeginningOfMonth() time.Time {
	return time.Date(t.Year(), t.Month(), 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

func (t *LocalTime) BeginningOfNextMonth() time.Time {
	return t.BeginningOfMonth().AddDate(0,1,0)
}


func createLocalTimeFrom(t time.Time, tz string, resetClock bool) (*LocalTime, error){
	location, err:= time.LoadLocation(tz)
	if err != nil {
		return nil, err
	}

	newTime := t.In(location)
	if resetClock {
		newTime = time.Date(newTime.Year(), newTime.Month() , newTime.Day(), 0,0,0,0, newTime.Location())
	}

	rt := &LocalTime{
		Time: newTime,
	}
	return rt, nil
}
