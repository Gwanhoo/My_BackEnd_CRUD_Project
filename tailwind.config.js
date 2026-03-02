/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.{ejs,html}",
    "./public/**/*.{html,js}"
  ],

  theme: {
    extend: {
      // 📌 spacing (pr-* 단위)
      spacing: {
        'pr-1': '1px',
        'pr-2': '2px',
        'pr-3': '3px',
        'pr-4': '4px',
        'pr-6': '6px',
        'pr-8': '8px',
        'pr-10': '10px',
        'pr-12': '12px',
        'pr-14': '14px',
        'pr-16': '16px',
        'pr-18': '18px',
        'pr-20': '20px',
        'pr-24': '24px',
        'pr-28': '28px',
        'pr-32': '32px',
        'pr-36': '36px',
        'pr-40': '40px',
        'pr-48': '48px',
        'pr-56': '56px',
        'pr-64': '64px',
        'pr-80': '80px',
        'pr-96': '96px',
        'pr-118': '118px',
        'pr-151': '151px',
        'pr-172': '172px',

        // width/height 전용 프리셋
        'pr-240': '240px',
        'pr-260': '260px',
        'pr-300': '300px',
        'pr-520': '520px',
        'pr-800': '800px',
      },

      // 📌 rounded-pr-*
      borderRadius: {
        'pr-4':  '4px',
        'pr-6':  '6px',
        'pr-8':  '8px',
        'pr-10': '10px',
        'pr-12': '12px',
        'pr-16': '16px',
        'pr-20': '20px',
        'pr-24': '24px',
        'pr-32': '32px',
        'pr-48': '48px',
      },

      // 📌 브랜드 컬러
      colors: {
        'b-primary':  '#005AFF',
        'b-secondary':'#F6F8FE',
        'b-tertiary': '#7AA8FF',
      },

      // 📌 그림자 preset
      boxShadow: {
        'elev-1': '0 2px 8px rgba(0,0,0,0.12)',
      },
    },
  },

  // ⬇⬇⬇ DaisyUI 포함시키는 최종 plugins
  plugins: [
    require('daisyui')
  ],

  // DaisyUI 기본 테마 설정 (원하면 변경 가능)
  daisyui: {
    themes: ["light"],
  }
};
