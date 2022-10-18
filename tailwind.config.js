/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["src/**/*.{js,jsx,css}"],
  theme: {
    extend: {
        animation: {
            spin: "spin 1.3s linear infinite",
            fadein: "fadein 0.5s linear"
        },
        keyframes: {
            fadein: {
                '0%': {
                    transform: 'translateY(50px)',
                    opacity: '0'
                },
                '100%': {
                    transform: 'none',
                    opacity: '1'
                }
            }
        }
    },
  },
  plugins: [],
}
