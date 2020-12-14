package localization

import (
	"testing"
	"time"
)


func TestCreateLocalTime(t *testing.T) {
	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i), 10, 10, 50, 0, 0, location)
		expectedValue := time.Date(2020, time.Month(i), 10, 10, 50, 0, 0, location)

		value, err := createLocalTimeFrom(testTime, location.String(), false)
		if err != nil {
			t.Error(err)
		}

		if value.Sub(expectedValue) != 0 {
			t.Errorf("time %s is not %s", value, expectedValue)
		}
	}
}


func TestCreateLocalTimeWithTimeReset(t *testing.T) {
	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i), 1, 10, 50, 0, 0, location)
		expectedValue := time.Date(2020, time.Month(i), 1, 0, 0, 0, 0, location)

		value, err := createLocalTimeFrom(testTime, location.String(), true)
		if err != nil {
			t.Error(err)
		}

		if value.Sub(expectedValue) != 0 {
			t.Errorf("time %s is not %s", value, expectedValue)
		}
	}
}

func TestBeginningOfMonth(t *testing.T) {

	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i),10,10,50,0,0, location)
		expectedValue := time.Date(2020, time.Month(i),1,10,50,0,0, location)

		localizedTime, err := createLocalTimeFrom(testTime, location.String(), false)
		if err != nil {
			t.Error(err)
		}
		value := localizedTime.BeginningOfMonth()

		if value.Sub(expectedValue) != 0  {
			t.Errorf( "time %s is not %s",value, expectedValue  )
		}
	}
}

func TestBeginningOfMonthWithTimeReset(t *testing.T) {

	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i),10,10,50,0,0, location)
		expectedValue := time.Date(2020, time.Month(i),1,0,0,0,0, location)

		localizedTime, err := createLocalTimeFrom(testTime, location.String(), true)
		if err != nil {
			t.Error(err)
		}
		value := localizedTime.BeginningOfMonth()

		if value.Sub(expectedValue) != 0  {
			t.Errorf( "time %s is not %s",value, expectedValue  )
		}
	}
}


func TestBeginningOfNextMonth(t *testing.T) {

	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i),10,10,50,0,0, location)
		expectedValue := time.Date(2020, time.Month(i) + 1,1,10,50,0,0, location)

		localizedTime, err := createLocalTimeFrom(testTime, location.String(), false)
		if err != nil {
			t.Error(err)
		}
		value := localizedTime.BeginningOfNextMonth()

		//fmt.Println(value)
		if value.Sub(expectedValue) != 0  {
			t.Errorf( "time %s is not %s",value, expectedValue  )
		}
	}
}


func TestBeginningOfNextMonthWithTimeReset(t *testing.T) {

	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i),10,0,0,0,0, location)
		expectedValue := time.Date(2020, time.Month(i) + 1,1,0,0,0,0, location)

		// t.Logf("%s %s",testTime , expectedValue)

		localizedTime, err := createLocalTimeFrom(testTime, location.String(), true)
		if err != nil {
			t.Error(err)
		}
		value := localizedTime.BeginningOfNextMonth()

		//fmt.Println(value)
		if value.Sub(expectedValue) != 0  {
			t.Errorf( "time %s is not %s",value, expectedValue  )
		}
	}
}


func TestBeginningOfNextMonthWithTimeResetTZDiff(t *testing.T) {

	//utc, _:= time.LoadLocation("UTC")
	location, _:= time.LoadLocation("Australia/Sydney")

	for i := 1; i <= 12; i++ {
		testTime := time.Date(2020, time.Month(i),1,0,0,0,0, location).Add(-1 * time.Minute).UTC()
		expectedValue := time.Date(2020, time.Month(i) ,1,0,0,0,0, location)

		t.Logf("%s %s",testTime , expectedValue)

		localizedTime, err := createLocalTimeFrom(testTime, location.String(), true)
		if err != nil {
			t.Error(err)
		}
		value := localizedTime.BeginningOfNextMonth()

		//fmt.Println(value)
		if value.Sub(expectedValue) != 0  {
			t.Errorf( "time %s is not %s",value, expectedValue  )
		}
	}
}
