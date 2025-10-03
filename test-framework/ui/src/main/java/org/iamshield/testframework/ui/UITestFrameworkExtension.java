package org.iamshield.testframework.ui;

import org.iamshield.testframework.TestFrameworkExtension;
import org.iamshield.testframework.injection.Supplier;
import org.iamshield.testframework.ui.page.PageSupplier;
import org.iamshield.testframework.ui.webdriver.ChromeHeadlessWebDriverSupplier;
import org.iamshield.testframework.ui.webdriver.ChromeWebDriverSupplier;
import org.iamshield.testframework.ui.webdriver.FirefoxHeadlessWebDriverSupplier;
import org.iamshield.testframework.ui.webdriver.FirefoxWebDriverSupplier;
import org.iamshield.testframework.ui.webdriver.HtmlUnitWebDriverSupplier;
import org.openqa.selenium.WebDriver;

import java.util.List;
import java.util.Map;

public class UITestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(
                new HtmlUnitWebDriverSupplier(),
                new ChromeHeadlessWebDriverSupplier(),
                new ChromeWebDriverSupplier(),
                new FirefoxHeadlessWebDriverSupplier(),
                new FirefoxWebDriverSupplier(),
                new PageSupplier()
        );
    }

    @Override
    public Map<Class<?>, String> valueTypeAliases() {
        return Map.of(
                WebDriver.class, "browser"
        );
    }

}
