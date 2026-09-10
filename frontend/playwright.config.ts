import{defineConfig,devices}from'@playwright/test'

export default defineConfig({
 testDir:'./e2e',fullyParallel:true,retries:process.env.CI?2:0,reporter:process.env.CI?'github':'list',
 use:{baseURL:'http://127.0.0.1:4173',trace:'retain-on-failure',screenshot:'only-on-failure',reducedMotion:'reduce'},
 webServer:{command:'npm run dev -- --port 4173 --strictPort',url:'http://127.0.0.1:4173',reuseExistingServer:!process.env.CI},
 projects:[{name:'chromium',use:{...devices['Desktop Chrome']}}],
})
