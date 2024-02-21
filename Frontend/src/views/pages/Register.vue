<template>
	<div>
		<!-- فرم ثبت‌نام -->
		<form @submit.prevent="registerUser">
			<input v-model="phone" type="text" placeholder="شماره تلفن" />
			<!-- دیگر فیلدهای فرم -->

			<button type="submit">ثبت نام</button>
		</form>
	</div>
</template>
  
<script>
import axios from 'axios';

export default {
	name:"RegisterView", 
	data() {
		return {
			phone: '',
		};
	},
	methods: {
		async registerUser() {
			try {
				const response = await axios.post('info/', {
				phone:this.phone
				}, {
				headers: {
					'Content-Type': 'application/json',
				}
				})

				console.log(response.data); // پاسخ از سرور
			} catch (error) {
				console.error(error); // خطا در صورت وجود
			}
		},
	},
};
</script>
  