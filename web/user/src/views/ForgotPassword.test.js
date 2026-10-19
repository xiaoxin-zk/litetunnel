// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import ForgotPassword from './ForgotPassword.vue'
import { authApi } from '../api'

const { push } = vi.hoisted(() => ({ push: vi.fn() }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push }) }))
vi.mock('../api', () => ({
  authApi: { mailStatus: vi.fn(), sendEmailCode: vi.fn(), resetPassword: vi.fn() }
}))

let wrapper
function mountPage() {
  wrapper = mount(ForgotPassword, {
    attachTo: document.body,
    global: { plugins: [ElementPlus], mocks: { $router: { push } } }
  })
  return wrapper
}
function button(text) {
  const found = wrapper.findAll('button').find((node) => node.text() === text)
  expect(found, `按钮不存在：${text}`).toBeDefined()
  return found
}
async function fillPasswords() {
  const inputs = wrapper.findAll('input[type="password"]')
  await inputs.at(-2).setValue('NewPassw0rd!')
  await inputs.at(-1).setValue('NewPassw0rd!')
}

beforeEach(() => {
  vi.clearAllMocks()
  authApi.mailStatus.mockReset()
  authApi.sendEmailCode.mockReset().mockResolvedValue({})
  authApi.resetPassword.mockReset().mockResolvedValue({})
  vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
  vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
})
afterEach(() => {
  wrapper?.unmount()
  ElMessage.closeAll()
  vi.restoreAllMocks()
  vi.useRealTimers()
  document.body.innerHTML = ''
})

describe('找回密码页面', () => {
  it('查询期间不提供表单，失败后保持未知且不调用恢复接口', async () => {
    let reject
    authApi.mailStatus.mockReturnValue(new Promise((_resolve, fail) => { reject = fail }))
    mountPage()
    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.findAll('input')).toHaveLength(0)
    reject(new Error('network unavailable'))
    await flushPromises()
    expect(wrapper.text()).toContain('邮件服务状态未知')
    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.findAll('button').some((node) => node.text() === '重置密码')).toBe(false)
    expect(authApi.resetPassword).not.toHaveBeenCalled()
    expect(authApi.sendEmailCode).not.toHaveBeenCalled()
    expect(button('重试查询').exists()).toBe(true)
  })

  it.each([true, false])('失败后重试成功，根据邮件开关 %s 切换正确模式', async (enabled) => {
    authApi.mailStatus.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ mail_enabled: enabled })
    mountPage()
    await flushPromises()
    await button('重试查询').trigger('click')
    await flushPromises()
    expect(authApi.mailStatus).toHaveBeenCalledTimes(2)
    expect(wrapper.find('form').exists()).toBe(true)
    expect(wrapper.find('input[placeholder="6 位验证码"]').exists()).toBe(enabled)
    expect(wrapper.find('input[placeholder="用于验证身份"]').exists()).toBe(!enabled)
    expect(wrapper.findAll('button').some((node) => node.text() === '获取验证码')).toBe(enabled)
  })

  it.each([{}, { mail_enabled: 'false' }, null])('无效状态响应不能降级为旧密码模式：%j', async (response) => {
    authApi.mailStatus.mockResolvedValue(response)
    mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('邮件服务状态未知')
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('用户名不能获取验证码，注册邮箱去除空白后请求并进入冷却', async () => {
    vi.useFakeTimers()
    authApi.mailStatus.mockResolvedValue({ mail_enabled: true })
    mountPage()
    await flushPromises()
    const account = wrapper.find('input[placeholder="请输入已验证的注册邮箱"]')
    await account.setValue('some_username')
    await button('获取验证码').trigger('click')
    expect(authApi.sendEmailCode).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalled()
    await account.setValue(' registered@example.com ')
    await button('获取验证码').trigger('click')
    await flushPromises()
    expect(authApi.sendEmailCode).toHaveBeenCalledExactlyOnceWith({ email: 'registered@example.com', scene: 'reset' })
    expect(button('60s').attributes('disabled')).toBeDefined()
    await vi.advanceTimersByTimeAsync(60000)
    expect(button('获取验证码').attributes('disabled')).toBeUndefined()
  })

  it('真实表单校验拒绝用户名和空验证码，合法输入才按邮箱模式提交', async () => {
    authApi.mailStatus.mockResolvedValue({ mail_enabled: true })
    mountPage()
    await flushPromises()
    const account = wrapper.find('input[placeholder="请输入已验证的注册邮箱"]')
    await account.setValue('username_only')
    await fillPasswords()
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('验证码流程不支持用户名')
    await account.setValue('registered@example.com')
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('请填写邮箱验证码')
    expect(authApi.resetPassword).not.toHaveBeenCalled()
    await wrapper.find('input[placeholder="6 位验证码"]').setValue('123456')
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).toHaveBeenCalledExactlyOnceWith({
      account: 'registered@example.com', email_code: '123456', old_password: '', password: 'NewPassw0rd!'
    })
    expect(push).toHaveBeenCalledWith('/login')
  })

  it('密码不够长或确认不一致时真实表单阻止提交', async () => {
    authApi.mailStatus.mockResolvedValue({ mail_enabled: true })
    mountPage()
    await flushPromises()
    await wrapper.find('input[placeholder="请输入已验证的注册邮箱"]').setValue('registered@example.com')
    await wrapper.find('input[placeholder="6 位验证码"]').setValue('123456')
    const passwords = wrapper.findAll('input[type="password"]')
    await passwords[0].setValue('short')
    await passwords[1].setValue('short')
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).not.toHaveBeenCalled()
    await passwords[0].setValue('NewPassw0rd!')
    await passwords[1].setValue('different')
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).not.toHaveBeenCalled()
  })

  it('确认未启用邮件后才允许旧密码模式，空旧密码不提交', async () => {
    authApi.mailStatus.mockResolvedValue({ mail_enabled: false })
    mountPage()
    await flushPromises()
    await wrapper.find('input[placeholder="请输入用户名或邮箱"]').setValue('username')
    await fillPasswords()
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('请填写当前密码')
    await wrapper.find('input[placeholder="用于验证身份"]').setValue('OldPassw0rd!')
    await button('重置密码').trigger('click')
    await flushPromises()
    expect(authApi.resetPassword).toHaveBeenCalledExactlyOnceWith({
      account: 'username', email_code: '', old_password: 'OldPassw0rd!', password: 'NewPassw0rd!'
    })
  })
})
