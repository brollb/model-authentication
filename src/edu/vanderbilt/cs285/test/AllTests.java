package edu.vanderbilt.cs285.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ ClientTest.class, ServerTest.class, UtilityTest.class })
public class AllTests {

}
