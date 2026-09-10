import AxeBuilder from'@axe-core/playwright'
import{expect,test,type Page}from'@playwright/test'

async function expectAccessible(page:Page){
 const results=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze()
 expect(results.violations.map(({id,impact,nodes})=>({id,impact,targets:nodes.map(node=>node.target)}))).toEqual([])
}

test('French authorization screen is accessible and keyboard focused',async({page})=>{
 const errors:string[]=[]
 page.on('console',message=>{if(message.type()==='error')errors.push(message.text())})
 await page.goto('/')
 await expect(page.getByRole('heading',{name:'Autorisation'})).toBeVisible()
 const demoButton=page.getByRole('button',{name:'Ouvrir la boutique de démonstration'})
 await demoButton.focus()
 await expect(demoButton).toBeFocused()
 expect(await demoButton.evaluate(element=>getComputedStyle(element).outlineStyle)).not.toBe('none')
 await expectAccessible(page)
 expect(errors).toEqual([])
})

test('Arabic RTL remains readable without horizontal overflow on mobile',async({page})=>{
 const errors:string[]=[]
 page.on('console',message=>{if(message.type()==='error')errors.push(message.text())})
 await page.setViewportSize({width:390,height:844})
 await page.goto('/')
 await page.getByLabel('Langue').selectOption('ar')
 await expect(page.locator('html')).toHaveAttribute('lang','ar')
 await expect(page.locator('html')).toHaveAttribute('dir','rtl')
 await expect(page.getByRole('heading',{name:'الترخيص'})).toBeVisible()
 expect(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
 await expectAccessible(page)
 expect(errors).toEqual([])
})

test('localized simulation cards stack on mobile',async({page})=>{
 await page.goto('/')
 await page.getByLabel('Langue').selectOption('ar')
 await page.getByRole('button',{name:'محاكاة محلية'}).click()
 await page.setViewportSize({width:390,height:844})
 await expect(page.getByRole('heading',{name:'تعرض مُحاكى'})).toBeVisible()
 await expect(page.getByText('SELECT … WHERE id = ? مع معامل محدد النوع')).toBeVisible()
 expect(await page.locator('.flow').evaluate(element=>getComputedStyle(element).gridTemplateColumns.split(' ').length)).toBe(1)
 expect(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
 await expectAccessible(page)
})
